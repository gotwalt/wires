# wires iOS UI Snapshot Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fixture-driven XCUITest harness that captures every notable iOS UI state of the Wires companion app as deterministic PNGs, runnable from a shell script with no live wires-host / wires-mcp / pair-partner required.

**Architecture:** A new `LaunchFixture` enum is read from `WIRES_FIXTURE` at app launch; matching cases call `prepareDependencies` to swap every external client for a canned fixture and seed `AppFeature.State` directly into the target screen. A new `WiresUITests/SnapshotSweep.swift` test class enumerates the 17 fixtures × 2 appearances, relaunching the app per cell, taking `XCUIScreen.main.screenshot()`, and writing PNGs to `Wires/screenshots/<run-id>/` on the host filesystem. `scripts/snapshot-ios.sh` drives it.

**Tech Stack:** Swift 6, SwiftUI, The Composable Architecture (TCA), `swift-dependencies` (`@DependencyClient`, `prepareDependencies`), XCTest / XCUITest, iPhone 17 Pro simulator (iOS 26.4, UDID `161DAE86-C4C7-47FE-B25E-1FAF251F93F6`).

**Environment note:** The project's `IPHONEOS_DEPLOYMENT_TARGET = 26.4`, so an iOS 26.4 simulator is required. If only an iOS 26.1 iPhone 17 Pro is installed, create the right one with: `xcrun simctl create "iPhone 17 Pro - 26.4" "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro" "com.apple.CoreSimulator.SimRuntime.iOS-26-4"`.

**Branch prerequisite:** This worktree branch must include the two infrastructure commits cherry-picked from main: `5d3c5a7 ios: fix Swift 6 build errors in OAuthSignInFeature` and `b1bf0fa ios: wire ApprovalFeature into OAuthSignInFeature pair branch`. They are already on the branch as of `260db0f` (T1).

**Build prerequisite:** Before any `xcodebuild` invocation on a fresh worktree, run `scripts/build-ioskit.sh` once to generate `Wires/WiresKit/Frameworks/wires.xcframework` (the UniFFI-built Rust→Swift binding bundle). Worktrees don't share this artifact.

**Spec:** `docs/superpowers/specs/2026-05-19-wires-ios-snapshot-tooling-design.md`. Read it before starting.

---

## Deviation from spec

The spec at §3 calls for a new `WiresSnapshotTests` UITest target. This plan **uses the existing `WiresUITests` target instead** for v1.

Reason: adding a fully-wired UITest target via direct `project.pbxproj` editing requires generating ~10 new UUID-keyed sections (PBXNativeTarget, XCConfigurationList, two PBXBuildConfigurations, PBXSourcesBuildPhase, PBXFrameworksBuildPhase, target dependency, file group, scheme entry, TargetAttributes entry) and is fragile when done by hand. The current `WiresUITests/WiresUITests.swift` is a stub with one no-op test, so there is no collision concern in v1.

When real XCUITests are added later, splitting `SnapshotSweep` into its own target is a small follow-up: cut the file, paste into a new target made via the Xcode UI, commit the resulting pbxproj diff.

This deviation is recorded in this plan, not in the spec.

---

## Test commands referenced repeatedly

```bash
# Working directory throughout this plan:
WORK=/Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr

# iPhone 17 Pro simulator (iOS 26.1):
SIM_UDID=161DAE86-C4C7-47FE-B25E-1FAF251F93F6

# Build the app for the simulator (no run):
xcodebuild build \
  -project "$WORK/Wires/Wires.xcodeproj" \
  -scheme Wires \
  -destination "platform=iOS Simulator,id=$SIM_UDID" \
  -quiet

# Run unit tests only (WiresTests):
xcodebuild test \
  -project "$WORK/Wires/Wires.xcodeproj" \
  -scheme Wires \
  -destination "platform=iOS Simulator,id=$SIM_UDID" \
  -only-testing:WiresTests \
  -quiet

# Run UI test sweep (WiresUITests/SnapshotSweep):
xcodebuild test \
  -project "$WORK/Wires/Wires.xcodeproj" \
  -scheme Wires \
  -destination "platform=iOS Simulator,id=$SIM_UDID" \
  -only-testing:WiresUITests/SnapshotSweep
```

If a build command times out, that's almost certainly an iOS simulator runtime download or first-build cold-start. Run it once interactively in Terminal to warm the build cache before retrying in the test loop.

---

## File structure

**Create:**

| Path | Role |
|---|---|
| `Wires/Wires/Dependencies/CameraPreviewKind.swift` | New TCA dependency `cameraPreviewKind: .live | .placeholder` |
| `Wires/Wires/Fixtures/FixtureRuntime.swift` | Singleton holder for the active fixture + utility helpers |
| `Wires/Wires/Fixtures/LaunchFixture.swift` | The enum, `install(named:)`, `applyDependencies(to:)`, `initialAppState`, `flowAndShortName` |
| `Wires/Wires/Fixtures/Appearance.swift` | `Appearance` enum (`.light`, `.dark`) shared by app + tests |
| `Wires/Wires/Fixtures/Fixtures+Household.swift` | `HouseholdClient.fixture(...)` constructor |
| `Wires/Wires/Fixtures/Fixtures+Wires.swift` | `WiresClient.fixture(...)` constructor |
| `Wires/Wires/Fixtures/Fixtures+MCPGateway.swift` | `MCPGatewayClient.fixture(...)` constructor |
| `Wires/Wires/Fixtures/Fixtures+Camera.swift` | `CameraPermissionClient.fixture(...)` constructor |
| `Wires/Wires/Features/Scan/FixtureCameraPlaceholder.swift` | The static viewfinder placeholder view |
| `Wires/WiresUITests/SnapshotSweep.swift` | The XCTest class with 17 test methods + `snap(_:)` helper |
| `Wires/WiresTests/LaunchFixtureTests.swift` | Two enum-shape sanity tests |
| `scripts/snapshot-ios.sh` | Driver script |

**Modify:**

| Path | Change |
|---|---|
| `Wires/Wires/Features/Scan/ScanView.swift` | Read `@Dependency(\.cameraPreviewKind)`, branch in `.granted` |
| `Wires/Wires/WiresApp.swift` | Read `WIRES_FIXTURE` / `WIRES_APPEARANCE` env, install fixture, apply appearance, skip `prepareWiresApp` |
| `Wires/Wires/Features/Home/HomeView.swift` | Skip `store.send(.onAppear)` when fixture active (preserves seeded state) |
| `.gitignore` | Add `Wires/screenshots/` |
| `CLAUDE.md` | One-line pointer under "Status" |

**Targets:** the Xcode project uses **synchronized folder groups** (Xcode 16's `PBXFileSystemSynchronizedRootGroup`). That means:
- Any file under `Wires/Wires/` is automatically in the `Wires` target.
- Any file under `Wires/WiresTests/` is automatically in the `WiresTests` target.
- Any file under `Wires/WiresUITests/` is automatically in the `WiresUITests` target.

No pbxproj editing or Xcode UI is needed. Just create the file in the correct directory and it's a target member. (You may need to verify this once for the first task by running `xcodebuild build` — if the build fails with "cannot find symbol X", the synchronized group is working but the import or target isn't right.)

---

## Task 1: CameraPreviewKind dependency + ScanView seam

**Files:**
- Create: `Wires/Wires/Dependencies/CameraPreviewKind.swift`
- Create: `Wires/Wires/Features/Scan/FixtureCameraPlaceholder.swift`
- Modify: `Wires/Wires/Features/Scan/ScanView.swift`

- [ ] **Step 1: Create CameraPreviewKind dependency**

Content of `Wires/Wires/Dependencies/CameraPreviewKind.swift`:

```swift
import ComposableArchitecture
import Dependencies

/// Which renderer ScanView should put inside the `.granted` branch.
///
/// `.live` instantiates an `AVCaptureSession`-backed view; `.placeholder`
/// renders a static viewfinder graphic. The latter is used for snapshot
/// fixtures (where the simulator has no camera) and could be used for
/// Xcode previews in the future.
enum CameraPreviewKind: Equatable, Sendable {
    case live
    case placeholder
}

extension DependencyValues {
    var cameraPreviewKind: CameraPreviewKind {
        get { self[CameraPreviewKindKey.self] }
        set { self[CameraPreviewKindKey.self] = newValue }
    }
}

private enum CameraPreviewKindKey: DependencyKey {
    static let liveValue: CameraPreviewKind = .live
}
```

- [ ] **Step 2: Create FixtureCameraPlaceholder view**

Content of `Wires/Wires/Features/Scan/FixtureCameraPlaceholder.swift`:

```swift
import SwiftUI

/// Static stand-in for the live camera preview. Used in snapshot fixture
/// runs. Visually mimics a viewfinder: dim background, centered reticle
/// SF Symbol. Does not instantiate an AVCaptureSession.
struct FixtureCameraPlaceholder: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.black, Color(white: 0.12)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            Image(systemName: "qrcode.viewfinder")
                .resizable()
                .scaledToFit()
                .frame(width: 220, height: 220)
                .foregroundStyle(.white.opacity(0.85))
                .shadow(color: .black.opacity(0.4), radius: 6, y: 2)
        }
    }
}
```

- [ ] **Step 3: Modify ScanView to consume the dependency**

The current `.granted` branch in `Wires/Wires/Features/Scan/ScanView.swift` is:

```swift
case .granted:
    CameraCaptureView { payload in
        store.send(.decoded(payload))
    }
    .ignoresSafeArea()

    if let err = store.error {
        errorBanner(err)
    }
```

Add the dependency to the struct (next to `@Bindable var store:`):

```swift
@Dependency(\.cameraPreviewKind) private var previewKind
```

And add `import Dependencies` if not already present (it's usually already in via `ComposableArchitecture`, but make sure).

Replace the `.granted` branch with:

```swift
case .granted:
    Group {
        switch previewKind {
        case .live:
            CameraCaptureView { payload in
                store.send(.decoded(payload))
            }
            .ignoresSafeArea()
        case .placeholder:
            FixtureCameraPlaceholder()
        }
    }

    if let err = store.error {
        errorBanner(err)
    }
```

- [ ] **Step 4: Verify file locations**

The two new files must sit at:
- `Wires/Wires/Dependencies/CameraPreviewKind.swift`
- `Wires/Wires/Features/Scan/FixtureCameraPlaceholder.swift`

Both are inside the synchronized group rooted at `Wires/Wires/`, so they're automatically members of the `Wires` target. No pbxproj edit needed.

- [ ] **Step 5: Build**

```bash
cd /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0. Errors will be unresolved imports or missing target membership — re-check Step 4.

- [ ] **Step 6: Commit**

```bash
git add Wires/Wires/Dependencies/CameraPreviewKind.swift \
        Wires/Wires/Features/Scan/FixtureCameraPlaceholder.swift \
        Wires/Wires/Features/Scan/ScanView.swift
git commit -m "$(cat <<'EOF'
ios: add CameraPreviewKind dependency seam

ScanView's .granted branch now picks between CameraCaptureView (live) and
FixtureCameraPlaceholder (placeholder) via @Dependency(\.cameraPreviewKind).
Production defaults to .live; the upcoming snapshot harness injects
.placeholder so the simulator (no camera) renders a deterministic
viewfinder graphic instead.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: FixtureRuntime + LaunchFixture skeleton

**Files:**
- Create: `Wires/Wires/Fixtures/FixtureRuntime.swift`
- Create: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Create: `Wires/Wires/Fixtures/Appearance.swift`
- Create: `Wires/WiresTests/LaunchFixtureTests.swift`

- [ ] **Step 1: Create FixtureRuntime**

Content of `Wires/Wires/Fixtures/FixtureRuntime.swift`:

```swift
import Foundation

/// Process-wide register of which fixture is active. Set once at app
/// launch by `LaunchFixture.install(named:)`. Views consult `isActive`
/// to skip work that would clobber seeded state (e.g. HomeView's
/// onAppear).
///
/// In production builds nothing writes to this; `activeFixture` stays
/// nil and `isActive` is always false. The struct is internal-only.
enum FixtureRuntime {
    static let shared = Storage()

    final class Storage {
        var activeFixture: LaunchFixture?
        var malformedFixtureName: String?
    }

    static var isActive: Bool { shared.activeFixture != nil }
}
```

- [ ] **Step 2: Create Appearance**

Content of `Wires/Wires/Fixtures/Appearance.swift`:

```swift
import Foundation
import UIKit

/// The two appearance settings the snapshot sweep cares about. Shared
/// between the app (reads `WIRES_APPEARANCE` at launch) and the UITest
/// (writes it into `launchEnvironment`).
enum Appearance: String, CaseIterable {
    case light
    case dark

    var uiStyle: UIUserInterfaceStyle {
        switch self {
        case .light: .light
        case .dark: .dark
        }
    }
}
```

- [ ] **Step 3: Create LaunchFixture skeleton**

Content of `Wires/Wires/Fixtures/LaunchFixture.swift` (initial skeleton — the per-case bodies of `applyDependencies` and `initialAppState` are stubs that will be filled in across Tasks 4a–4d):

```swift
import ComposableArchitecture
import Dependencies
import Foundation

/// Every notable UI state of the app, identified by a stable string the
/// snapshot test target writes into `WIRES_FIXTURE` at launch.
///
/// Adding a fixture:
///   1. Add an enum case + raw value here.
///   2. Add an arm to `applyDependencies(to:)` setting the dependencies
///      the seeded screen relies on.
///   3. Add an arm to `initialAppState` returning the AppFeature.State
///      the app should land in.
///   4. Add a test method in WiresUITests/SnapshotSweep.swift.
enum LaunchFixture: String, CaseIterable {
    case bootstrapScanDenied        = "bootstrap_scan_denied"
    case bootstrapScanGranted       = "bootstrap_scan_granted"
    case bootstrapConfirm           = "bootstrap_confirm"
    case bootstrapDone              = "bootstrap_done"
    case homeLoading                = "home_loading"
    case homeEmpty                  = "home_empty"
    case homeOneCap                 = "home_one_cap"
    case homeThreeCapsOneRevoked    = "home_three_caps_one_revoked"
    case enrollScan                 = "enroll_scan"
    case enrollApprovePristine      = "enroll_approve_pristine"
    case enrollApprovePartial       = "enroll_approve_partial"
    case enrollDone                 = "enroll_done"
    case oauthScan                  = "oauth_scan"
    case oauthSigninConfirm         = "oauth_signin_confirm"
    case oauthPairApprove           = "oauth_pair_approve"
    case oauthDone                  = "oauth_done"
    case oauthError                 = "oauth_error"

    /// Reads `WIRES_FIXTURE` from the environment and, if valid, installs
    /// the corresponding fixture dependencies and records it as the
    /// active fixture. Called once at app launch.
    static func install(named raw: String) {
        guard let fix = LaunchFixture(rawValue: raw) else {
            FixtureRuntime.shared.malformedFixtureName = raw
            return
        }
        FixtureRuntime.shared.activeFixture = fix
        prepareDependencies { values in
            fix.applyDependencies(to: &values)
        }
    }

    /// (filled in by Task 3 + 4a–4d)
    func applyDependencies(to values: inout DependencyValues) {
        // Default placeholder dependencies that work for every fixture:
        // .placeholder camera so no AVCaptureSession spins up.
        values.cameraPreviewKind = .placeholder
        // Per-fixture overrides land in switch arms below as tasks 4a-4d
        // are implemented.
        switch self {
        case .bootstrapScanDenied, .bootstrapScanGranted, .bootstrapConfirm, .bootstrapDone,
             .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
             .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
             .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
            break  // filled in by Task 4
        }
    }

    /// (filled in by Task 4a–4d)
    var initialAppState: AppFeature.State {
        // Stub — every case returns .launching until Task 4 fills it.
        return .launching
    }

    /// Maps each fixture to a (flow folder, short filename) tuple. Used
    /// by `SnapshotSweep` to compute the output path.
    var flowAndShortName: (flow: String, short: String) {
        let raw = rawValue
        if let underscore = raw.firstIndex(of: "_") {
            let flow = String(raw[..<underscore])
            let rest = raw[raw.index(after: underscore)...]
                .replacingOccurrences(of: "_", with: "-")
            return (flow, rest)
        }
        return ("misc", raw)
    }
}
```

- [ ] **Step 4: Add LaunchFixture sanity tests**

Content of `Wires/WiresTests/LaunchFixtureTests.swift`:

```swift
import XCTest
@testable import Wires

final class LaunchFixtureTests: XCTestCase {

    /// Catches typo regressions: every case's rawValue must round-trip
    /// through the failable initializer. This is the contract the env
    /// var system relies on.
    func test_rawValue_roundTrips_for_every_case() {
        for fixture in LaunchFixture.allCases {
            let resolved = LaunchFixture(rawValue: fixture.rawValue)
            XCTAssertEqual(resolved, fixture,
                "LaunchFixture(rawValue: \(fixture.rawValue)) did not round-trip")
        }
    }

    /// Catches accidental case drops. v1 ships exactly 17 fixtures per
    /// the spec §4.4. Update this number deliberately if the fixture
    /// catalogue changes.
    func test_allCases_count_matches_spec() {
        XCTAssertEqual(LaunchFixture.allCases.count, 17)
    }
}
```

- [ ] **Step 5: Verify file locations**

The four new files must sit at:
- `Wires/Wires/Fixtures/FixtureRuntime.swift`
- `Wires/Wires/Fixtures/LaunchFixture.swift`
- `Wires/Wires/Fixtures/Appearance.swift`
- `Wires/WiresTests/LaunchFixtureTests.swift`

The first three are in the `Wires` target's synchronized group; the
fourth is in the `WiresTests` synchronized group. Creating them at
those paths is sufficient — no Xcode UI or pbxproj edits.

The `Fixtures` directory does not exist yet; just `mkdir -p
Wires/Wires/Fixtures` before writing the files (or rely on the Write
tool to create it).

- [ ] **Step 6: Build**

```bash
cd /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0. Common failures: missing target membership ("AppFeature not found") — re-check Step 5.

- [ ] **Step 7: Run the new unit tests**

```bash
xcodebuild test \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -only-testing:WiresTests/LaunchFixtureTests \
  -quiet
```

Expected: 2 tests pass, exit 0.

- [ ] **Step 8: Commit**

```bash
git add Wires/Wires/Fixtures/ Wires/WiresTests/LaunchFixtureTests.swift
git commit -m "$(cat <<'EOF'
ios: add LaunchFixture / FixtureRuntime / Appearance skeleton

LaunchFixture is the registry of every notable UI state for the
upcoming snapshot harness — 17 cases identified by stable rawValues
matching WIRES_FIXTURE env values. Per-case applyDependencies and
initialAppState bodies are stubs in this commit; Task 3 wires the
per-dependency fixture constructors and Tasks 4a–4d fill in the cases.

Sanity tests guard against rawValue typos and accidental case drops
(spec §11).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Per-dependency fixture constructors

**Files:**
- Create: `Wires/Wires/Fixtures/Fixtures+Household.swift`
- Create: `Wires/Wires/Fixtures/Fixtures+Wires.swift`
- Create: `Wires/Wires/Fixtures/Fixtures+MCPGateway.swift`
- Create: `Wires/Wires/Fixtures/Fixtures+Camera.swift`

- [ ] **Step 1: HouseholdClient.fixture**

Content of `Wires/Wires/Fixtures/Fixtures+Household.swift`:

```swift
import Foundation
import WiresKit

extension HouseholdClient {
    /// Canned in-memory household for snapshot fixtures. Returns
    /// fully-constructed (but never persisted) SwiftData @Model
    /// instances. Writes are no-ops. Use the `block` flag on
    /// `listCapsBehavior` to simulate the loading spinner.
    static func fixture(
        household: Household? = nil,
        caps: [CapRecord] = [],
        topics: [TopicRecord] = [],
        listCapsBehavior: ListBehavior = .return
    ) -> HouseholdClient {
        HouseholdClient(
            loadHousehold: { household },
            saveHousehold: { _ in },
            refreshHostInfo: { _, _, _, _ in },
            listTopics: { topics },
            saveTopic: { _ in },
            markTopicRegistered: { _ in },
            listCaps: {
                switch listCapsBehavior {
                case .return:
                    return caps
                case .block:
                    try? await Task.sleep(for: .seconds(60))
                    return caps
                }
            },
            saveCap: { _ in },
            wipeAll: { }
        )
    }

    enum ListBehavior: Sendable {
        /// Return `caps` immediately.
        case `return`
        /// Sleep 60 s before returning. Use for `home_loading` so the
        /// reducer's loading=true state is captured.
        case block
    }
}
```

- [ ] **Step 2: WiresClient.fixture**

Content of `Wires/Wires/Fixtures/Fixtures+Wires.swift`:

```swift
import Foundation
import WiresKit

extension WiresClient {
    /// No-op fixture. Every method returns a stub value or no-op
    /// completes. Suitable for any fixture screen that doesn't actually
    /// invoke FFI — which is all of them, because fixture mode skips
    /// `prepareWiresApp` and the seeded AppFeature.State puts the user
    /// past any view that would dispatch a Wires effect on its own.
    static func fixture() -> WiresClient {
        WiresClient(
            bootstrap: { _, _ in },
            parseHostTicket: { _ in
                HostInfo(
                    endpointIdHex: String(repeating: "ab", count: 32),
                    addrs: ["10.0.0.1:4242"],
                    relay: nil,
                    hintExpiresAtMs: 0
                )
            },
            registerWithHostedService: { _ in
                TenantRegistration(
                    hostEndpointIdHex: String(repeating: "ab", count: 32),
                    capsTopicIdHex: String(repeating: "cd", count: 32)
                )
            },
            registerTopic: { _, _ in },
            unregisterTenant: { _ in
                UnregisterResult(tenantsDropped: 1, topicsDropped: 0)
            },
            parsePairRequest: { _ in
                PairRequestPreview(
                    handle: PendingPairHandle(id: "fixture-pair"),
                    agentPubkeyHex: String(repeating: "ef", count: 32),
                    role: "agent",
                    description: "Aaron's Mac",
                    requestedScopes: []
                )
            },
            generateTopicIdAndEpoch0: {
                NewTopic(topicIdHex: String(repeating: "00", count: 32), epoch0Key: Data(repeating: 0, count: 32))
            },
            approvePairRequest: { _, _, _ in
                PairAckRecord(
                    installedCapIdHex: String(repeating: "11", count: 32),
                    installedAtMs: 0
                )
            },
            discardPairRequest: { _ in },
            reset: { }
        )
    }
}
```

Note: if any of these initializer signatures don't match WiresKit's
generated FFI types exactly, fix the field names against
`Wires/WiresKit/Sources/WiresKit/Wires.swift` (auto-generated by UniFFI).
The names above are the current ones as of writing.

- [ ] **Step 3: MCPGatewayClient.fixture**

Content of `Wires/Wires/Fixtures/Fixtures+MCPGateway.swift`:

```swift
import Foundation

extension MCPGatewayClient {
    /// No-op fixture. probe / postAssertion return inert defaults. The
    /// OAuth fixtures land the user past the probe step, so these are
    /// rarely exercised; they exist as safety nets.
    static func fixture() -> MCPGatewayClient {
        MCPGatewayClient(
            probe: { _, _, _ in
                .signin(challengeB64: "fixture-challenge")
            },
            postAssertion: { _, _, _, _ in }
        )
    }
}
```

- [ ] **Step 4: CameraPermissionClient.fixture**

Content of `Wires/Wires/Fixtures/Fixtures+Camera.swift`:

```swift
import Foundation

extension CameraPermissionClient {
    /// Returns `status` from `current` and `request`. No system prompt
    /// ever pops in the simulator.
    static func fixture(_ status: ScanPermissionStatus) -> CameraPermissionClient {
        CameraPermissionClient(
            current: { status },
            request: { status }
        )
    }
}
```

- [ ] **Step 5: Verify file locations**

All four new files sit under `Wires/Wires/Fixtures/`, already inside
the `Wires` target's synchronized group. No Xcode UI step needed.

- [ ] **Step 6: Build**

```bash
cd /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0. If a WiresKit type name doesn't match (e.g. `PendingPairHandle(opaque:)`), check `Wires/Wires/Models/CapRecord.swift`, `Wires/Wires/Models/Household.swift` etc. or the UniFFI-generated `Wires/WiresKit/Sources/WiresKit/Wires.swift` and adjust.

- [ ] **Step 7: Commit**

```bash
git add Wires/Wires/Fixtures/Fixtures+*.swift
git commit -m "$(cat <<'EOF'
ios: add per-dependency fixture constructors

HouseholdClient.fixture returns canned caps + household. WiresClient,
MCPGatewayClient, CameraPermissionClient fixtures are no-op stubs that
make every method safe to call. These compose into the per-fixture
overrides LaunchFixture.applyDependencies installs in Tasks 4a–4d.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4a: Bootstrap fixtures (4 cases)

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`

This task fills in the four `bootstrap*` cases in `applyDependencies(to:)` and `initialAppState`.

- [ ] **Step 1: Update applyDependencies switch**

Replace the placeholder switch block in `applyDependencies(to:)` so the four bootstrap cases set their dependencies:

```swift
func applyDependencies(to values: inout DependencyValues) {
    // Default: placeholder camera so no AVCaptureSession spins up.
    values.cameraPreviewKind = .placeholder

    switch self {
    case .bootstrapScanDenied:
        values.cameraPermissionClient = .fixture(.denied)
        values.wiresClient = .fixture()
        values.householdClient = .fixture()
        values.mcpGatewayClient = .fixture()

    case .bootstrapScanGranted:
        values.cameraPermissionClient = .fixture(.granted)
        values.wiresClient = .fixture()
        values.householdClient = .fixture()
        values.mcpGatewayClient = .fixture()

    case .bootstrapConfirm:
        values.cameraPermissionClient = .fixture(.granted)
        values.wiresClient = .fixture()
        values.householdClient = .fixture()
        values.mcpGatewayClient = .fixture()

    case .bootstrapDone:
        values.cameraPermissionClient = .fixture(.granted)
        values.wiresClient = .fixture()
        values.householdClient = .fixture()
        values.mcpGatewayClient = .fixture()

    case .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
         .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
         .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
        break  // filled in by Tasks 4b–4d
    }
}
```

- [ ] **Step 2: Update initialAppState**

Replace the stub `initialAppState` with:

```swift
var initialAppState: AppFeature.State {
    switch self {
    case .bootstrapScanDenied:
        var s = BootstrapFeature.State()
        s.scan.cameraPermission = .denied
        return .bootstrap(s)

    case .bootstrapScanGranted:
        var s = BootstrapFeature.State()
        s.scan.cameraPermission = .granted
        return .bootstrap(s)

    case .bootstrapConfirm:
        var s = BootstrapFeature.State()
        s.scan.cameraPermission = .granted
        s.confirmedHost = HostInfo(
            endpointIdHex: String(repeating: "ab", count: 32),
            addrs: ["192.168.1.20:4242"],
            relay: "https://relay.example.org",
            hintExpiresAtMs: 0
        )
        return .bootstrap(s)

    case .bootstrapDone:
        var s = BootstrapFeature.State()
        s.scan.cameraPermission = .granted
        let host = HostInfo(
            endpointIdHex: String(repeating: "ab", count: 32),
            addrs: ["192.168.1.20:4242"],
            relay: "https://relay.example.org",
            hintExpiresAtMs: 0
        )
        s.completed = BootstrapFeature.State.Completed(
            registration: TenantRegistration(
                capsTopicIdHex: String(repeating: "cd", count: 32),
                hostEndpointIdHex: host.endpointIdHex,
                serverTimeMs: 0
            ),
            host: host,
            rootPubkeyHex: String(repeating: "ab", count: 32)
        )
        return .bootstrap(s)

    case .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
         .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
         .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
        return .launching  // filled in by Tasks 4b–4d
    }
}
```

- [ ] **Step 3: Build**

```bash
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift
git commit -m "$(cat <<'EOF'
ios: fill in bootstrap snapshot fixtures (4)

bootstrapScanDenied / bootstrapScanGranted / bootstrapConfirm /
bootstrapDone now produce seeded BootstrapFeature.State + matching
dependency overrides. Other flows still stubbed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4b: Home fixtures (4 cases)

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`

- [ ] **Step 1: Add home arms to applyDependencies**

Replace the catch-all `case .homeLoading, .homeEmpty, …` arm in `applyDependencies(to:)` with individual home arms, leaving enroll/oauth in the catch-all:

```swift
case .homeLoading:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(listCapsBehavior: .block)
    values.mcpGatewayClient = .fixture()

case .homeEmpty:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        ),
        caps: []
    )
    values.mcpGatewayClient = .fixture()

case .homeOneCap:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    let cap = CapRecord(
        capIdHex: String(repeating: "11", count: 32),
        nodePubkeyHex: String(repeating: "aa", count: 32),
        nodeAlias: "Aaron's Mac",
        topicNames: ["family"],
        rights: ["read", "write"],
        issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
    )
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        ),
        caps: [cap]
    )
    values.mcpGatewayClient = .fixture()

case .homeThreeCapsOneRevoked:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    let macFamily = CapRecord(
        capIdHex: String(repeating: "11", count: 32),
        nodePubkeyHex: String(repeating: "aa", count: 32),
        nodeAlias: "Aaron's Mac",
        topicNames: ["family"],
        rights: ["read", "write"],
        issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
    )
    let iPadCalendar = CapRecord(
        capIdHex: String(repeating: "22", count: 32),
        nodePubkeyHex: String(repeating: "bb", count: 32),
        nodeAlias: "Kitchen iPad",
        topicNames: ["calendar"],
        rights: ["read"],
        issuedAt: Date(timeIntervalSince1970: 1_715_100_000),
        revokedAt: Date(timeIntervalSince1970: 1_715_200_000)
    )
    let hassMqtt = CapRecord(
        capIdHex: String(repeating: "33", count: 32),
        nodePubkeyHex: String(repeating: "cc", count: 32),
        nodeAlias: nil,
        topicNames: ["mqtt:hass"],
        rights: ["read", "write"],
        issuedAt: Date(timeIntervalSince1970: 1_715_300_000)
    )
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        ),
        caps: [macFamily, iPadCalendar, hassMqtt]
    )
    values.mcpGatewayClient = .fixture()
```

(Keep the remaining `case .enrollScan, .enrollApprovePristine, …, .oauthError` arm at `break`.)

- [ ] **Step 2: Add home arms to initialAppState**

Replace the catch-all for home + enroll + oauth with separate home arms (leave enroll/oauth still going to `.launching`):

```swift
case .homeLoading:
    var s = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    s.loading = true
    return .home(s)

case .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked:
    // HomeFeature.onAppear will call householdClient.listCaps which the
    // per-fixture override returns immediately. Set loading=false so
    // the brief flash before the effect resolves isn't .loading; the
    // effect resolves and overwrites caps from the client.
    return .home(HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32)))

case .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
     .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthError, .oauthDone:
    return .launching  // filled in by Tasks 4c–4d
```

Note: `.homeLoading` does NOT skip onAppear — `loading=true` is set up front and then the blocking fixture client keeps it that way past the 600ms screenshot moment. `.homeEmpty/.homeOneCap/.homeThreeCapsOneRevoked` rely on onAppear firing and reading the fixture client.

- [ ] **Step 3: Build**

```bash
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift
git commit -m "$(cat <<'EOF'
ios: fill in home snapshot fixtures (4)

homeLoading / homeEmpty / homeOneCap / homeThreeCapsOneRevoked seed
HomeFeature.State with rootPubkeyHex and let onAppear pull caps from
the fixture HouseholdClient (which returns the canned set immediately,
except homeLoading where it blocks 60s to keep loading=true visible).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4c: Enroll fixtures (4 cases)

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`

- [ ] **Step 1: Add enroll arms to applyDependencies**

Insert these arms in the switch (before the residual `.oauthScan…` catch-all arm):

```swift
case .enrollScan:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        )
    )
    values.mcpGatewayClient = .fixture()

case .enrollApprovePristine, .enrollApprovePartial, .enrollDone:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        )
    )
    values.mcpGatewayClient = .fixture()
```

- [ ] **Step 2: Add enroll arms to initialAppState**

The enroll fixtures all sit inside HomeView's `nodeEnrollment` sheet. Replace the residual enroll cases in the switch:

```swift
case .enrollScan:
    let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: [],
        relay: nil,
        hintExpiresAtMs: 0
    )
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    var enroll = NodeEnrollmentFeature.State.initial(host: host)
    // Pre-grant camera so the scan view shows the placeholder, not the
    // permission-request spinner.
    if case .scan(var scanStep) = enroll {
        scanStep.scan.cameraPermission = .granted
        enroll = .scan(scanStep)
    }
    home.nodeEnrollment = enroll
    return .home(home)

case .enrollApprovePristine:
    let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: [],
        relay: nil,
        hintExpiresAtMs: 0
    )
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    let preview = PairRequestPreview(
        handle: PendingPairHandle(id: "fixture-pair"),
        agentPubkeyHex: String(repeating: "ef", count: 32),
        role: "agent",
        description: "Aaron's Mac",
        issuedAtMs: 0,
        expiresAtMs: 0,
        requestedScopes: [
            RequestedScopePreview(topicName: "family", rights: [.read, .write]),
            RequestedScopePreview(topicName: "calendar", rights: [.read])
        ],
        dialSummary: ""
    )
    home.nodeEnrollment = .approve(ApprovalFeature.State(preview: preview, host: host))
    return .home(home)

case .enrollApprovePartial:
    let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: [],
        relay: nil,
        hintExpiresAtMs: 0
    )
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    let preview = PairRequestPreview(
        handle: PendingPairHandle(id: "fixture-pair"),
        agentPubkeyHex: String(repeating: "ef", count: 32),
        role: "agent",
        description: "Aaron's Mac",
        issuedAtMs: 0,
        expiresAtMs: 0,
        requestedScopes: [
            RequestedScopePreview(topicName: "family", rights: [.read, .write]),
            RequestedScopePreview(topicName: "calendar", rights: [.read])
        ],
        dialSummary: ""
    )
    var approve = ApprovalFeature.State(preview: preview, host: host)
    // Default state grants everything. Mutate to partial:
    //   - family: only .read granted (drop .write)
    //   - calendar: scope toggled off entirely
    if var fam = approve.decisions[id: "family"] {
        fam.grantedRights = [.read]
        approve.decisions[id: "family"] = fam
    }
    if var cal = approve.decisions[id: "calendar"] {
        cal.granted = false
        approve.decisions[id: "calendar"] = cal
    }
    home.nodeEnrollment = .approve(approve)
    return .home(home)

case .enrollDone:
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    let preview = PairRequestPreview(
        handle: PendingPairHandle(id: "fixture-pair"),
        agentPubkeyHex: String(repeating: "ef", count: 32),
        role: "agent",
        description: "Aaron's Mac",
        issuedAtMs: 0,
        expiresAtMs: 0,
        requestedScopes: [],
        dialSummary: ""
    )
    let ack = PairAckRecord(
        installedCapIdHex: String(repeating: "11", count: 32),
        installedAtMs: 0
    )
    home.nodeEnrollment = .done(NodeEnrollmentFeature.DoneStepState(ack: ack, preview: preview))
    return .home(home)
```

(Leave `.oauthScan, …, .oauthError` going to `.launching`.)

- [ ] **Step 3: Verify the `RequestedScopePreview` initializer**

`RequestedScopePreview(topicName:rights:)` is from WiresKit (note: the type is `RequestedScopePreview` post-T3 — the unprefixed `RequestedScope` is a different FFI type used in the approve flow, not the preview). Field names may differ. If the build errors complain, open `Wires/WiresKit/Sources/WiresKit/WiresKit.swift` and search for `struct RequestedScopePreview` to confirm. Likewise verify `Right.read` / `Right.write` enum cases (if it's `.READ` / `.WRITE`, adjust accordingly — UniFFI keeps Rust's casing in some configs).

- [ ] **Step 4: Build**

```bash
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift
git commit -m "$(cat <<'EOF'
ios: fill in node-enrollment snapshot fixtures (4)

enrollScan seeds Home → nodeEnrollment sheet at the scan step (with
camera pre-granted so the placeholder shows immediately).
enrollApprovePristine/Partial seed ApprovalFeature.State directly with
PairRequestPreview content (partial mutates a decision to read-only +
toggles a scope off). enrollDone seeds the post-approve terminal.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4d: OAuth fixtures (5 cases)

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`

- [ ] **Step 1: Add oauth arms to applyDependencies**

Replace the residual `.oauthScan, …, .oauthError` catch-all with:

```swift
case .oauthScan,
     .oauthSigninConfirm,
     .oauthPairApprove,
     .oauthDone,
     .oauthError:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32)
        )
    )
    values.mcpGatewayClient = .fixture()
```

(The switch's default-`break` arm should now be empty — the compiler will warn if there's nothing else to match. If you used `default:`, switch it to an explicit list of remaining cases or remove it.)

- [ ] **Step 2: Add oauth arms to initialAppState**

Replace the residual oauth catch-all with explicit arms:

```swift
case .oauthScan:
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    var oauth = OAuthSignInFeature.State.initial()
    if case .scan(var scanState) = oauth {
        scanState.cameraPermission = .granted
        oauth = .scan(scanState)
    }
    home.oauthSignIn = oauth
    return .home(home)

case .oauthSigninConfirm:
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    let ticket = SessionTicket(
        version: 1,
        kind: SessionTicket.kindV1,
        gatewayURL: "https://wires-mcp.example.org",
        sessionID: "fixture-session-id-abc"
    )
    let challenge = SignInChallenge(
        version: 1,
        kind: SignInChallenge.kindV1,
        gatewayURL: "https://wires-mcp.example.org",
        sessionID: "fixture-session-id-abc",
        nonce: String(repeating: "0", count: 64),
        issuedAt: 0,
        expires: 0
    )
    home.oauthSignIn = .signinConfirm(ticket: ticket, challenge: challenge)
    return .home(home)

case .oauthPairApprove:
    // The OAuth pair-approve state was rewired (commit b1bf0fa) to embed
    // ApprovalFeature.State directly — same payload as enrollApprovePristine.
    let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: [],
        relay: nil,
        hintExpiresAtMs: 0
    )
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    let preview = PairRequestPreview(
        handle: PendingPairHandle(id: "fixture-pair"),
        agentPubkeyHex: String(repeating: "ef", count: 32),
        role: "agent",
        description: "wires-mcp gateway",
        issuedAtMs: 0,
        expiresAtMs: 0,
        requestedScopes: [
            RequestedScopePreview(topicName: "wires-mcp:claude.ai", rights: [.read, .write])
        ],
        dialSummary: ""
    )
    home.oauthSignIn = .pairApprove(ApprovalFeature.State(preview: preview, host: host))
    return .home(home)

case .oauthDone:
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    home.oauthSignIn = .done(message: "Signed in")
    return .home(home)

case .oauthError:
    var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    home.oauthSignIn = .error(message: "gateway returned 500")
    return .home(home)
```

- [ ] **Step 3: Verify SessionTicket / SignInChallenge init signatures**

`SessionTicket` is defined in `Wires/Wires/Models/SessionTicket.swift`; `SignInChallenge` is in `Wires/Wires/Models/SignInChallenge.swift`. The names above (`gatewayURL`, `sessionID`, `version`, `nonce`, `expiresAtMs`) are based on the current models. If the build complains, open those files and adjust.

- [ ] **Step 4: Build**

```bash
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0. The switch should now be exhaustive over every `LaunchFixture` case in both `applyDependencies` and `initialAppState`.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift
git commit -m "$(cat <<'EOF'
ios: fill in OAuth sign-in snapshot fixtures (5)

oauthScan / oauthSigninConfirm / oauthPairApprove / oauthDone /
oauthError seed Home → oauthSignIn sheet directly into each state.
Scan step pre-grants camera so the placeholder renders immediately.
All 17 LaunchFixture cases now have a complete fixture; the next task
wires WiresIOSApp to install them at launch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: WiresIOSApp env wiring + onAppear guard

**Files:**
- Modify: `Wires/Wires/WiresApp.swift`
- Modify: `Wires/Wires/Features/Home/HomeView.swift`

- [ ] **Step 1: Replace WiresIOSApp body**

Replace the entire contents of `Wires/Wires/WiresApp.swift` with:

```swift
import ComposableArchitecture
import CryptoKit
import SwiftUI
import UIKit
import WiresKit

/// Renamed from `WiresApp` to avoid clashing with `WiresKit.WiresApp`
/// (the UniFFI-generated FFI class) within this module.
@main
struct WiresIOSApp: App {
    static let store: StoreOf<AppFeature> = {
        if let raw = ProcessInfo.processInfo.environment["WIRES_FIXTURE"] {
            LaunchFixture.install(named: raw)
            let initial = LaunchFixture(rawValue: raw)?.initialAppState ?? .launching
            return Store(initialState: initial) { AppFeature() }
        }
        return Store(initialState: .launching) { AppFeature() }
    }()

    var body: some Scene {
        WindowGroup {
            AppView(store: Self.store)
                .task {
                    if !FixtureRuntime.isActive {
                        Self.store.send(.onAppear)
                    }
                }
                .onAppear {
                    applyFixtureAppearanceIfNeeded()
                }
        }
    }

    /// Reads `WIRES_APPEARANCE` and forces the key window's interface
    /// style. No-op when the env var is unset or unrecognized.
    @MainActor
    private func applyFixtureAppearanceIfNeeded() {
        guard
            let raw = ProcessInfo.processInfo.environment["WIRES_APPEARANCE"],
            let appearance = Appearance(rawValue: raw)
        else { return }

        for scene in UIApplication.shared.connectedScenes {
            guard let windowScene = scene as? UIWindowScene else { continue }
            for window in windowScene.windows {
                window.overrideUserInterfaceStyle = appearance.uiStyle
            }
        }
    }
}

struct AppView: View {
    let store: StoreOf<AppFeature>

    var body: some View {
        switch store.state {
        case .launching:
            ProgressView()
        case .bootstrap:
            if let scoped = store.scope(state: \.bootstrap, action: \.bootstrap) {
                BootstrapView(store: scoped)
            }
        case .home:
            if let scoped = store.scope(state: \.home, action: \.home) {
                HomeView(store: scoped)
            }
        }
    }
}

/// One-time startup plumbing: makes sure the Keychain holds an iroh node
/// secret + a root signing keypair, then calls `WiresClient.bootstrap` so
/// downstream FFI calls work. Idempotent.
private let irohSecretAccount = "wires.iroh.secret"

@Sendable
func prepareWiresApp(
    keychain: KeychainClient,
    wires: WiresClient
) async {
    let irohSecret: Data
    if let existing = try? keychain.getData(account: irohSecretAccount), !existing.isEmpty {
        irohSecret = existing
    } else {
        var fresh = Data(count: 32)
        fresh.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress {
                _ = SecRandomCopyBytes(kSecRandomDefault, 32, base)
            }
        }
        try? keychain.setData(
            account: irohSecretAccount,
            value: fresh,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        irohSecret = fresh
    }

    let hadPubkey = (try? keychain.getData(account: KeychainBackedRootSigner.Account.pubkey)) != nil
    if !hadPubkey {
        let key = Curve25519.Signing.PrivateKey()
        try? keychain.setData(
            account: KeychainBackedRootSigner.Account.signingKey,
            value: key.rawRepresentation,
            accessibility: .afterFirstUnlockThisDeviceOnlyBiometricCurrentSet
        )
        try? keychain.setData(
            account: KeychainBackedRootSigner.Account.pubkey,
            value: key.publicKey.rawRepresentation,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
    }

    guard let signer = try? KeychainBackedRootSigner.tryLoad(keychain: keychain) else {
        return
    }
    await wires.bootstrap(irohSecret, signer)
}
```

Key changes vs. the existing file:
- The `store` is now built inside a closure that first checks `WIRES_FIXTURE`. If set, installs the fixture and uses its `initialAppState`.
- The original `.task { store.send(.onAppear) }` on AppView became `.task { if !FixtureRuntime.isActive { store.send(.onAppear) } }` — fixture mode does not run the keychain/household bootstrap.
- New `.onAppear { applyFixtureAppearanceIfNeeded() }` reads `WIRES_APPEARANCE` and forces the window style.
- `prepareWiresApp` is unchanged.
- `AppView` is unchanged structurally; the `.task` block previously inside AppView's `.launching` case moves up to the WindowGroup level so it can run in any mode.

- [ ] **Step 2: Guard HomeView's onAppear task in fixture mode**

In `Wires/Wires/Features/Home/HomeView.swift`, the existing `.task { store.send(.onAppear) }` (around line 36) becomes:

```swift
.task {
    if !FixtureRuntime.isActive {
        store.send(.onAppear)
    } else if shouldFireOnAppearInFixtureMode {
        store.send(.onAppear)
    }
}
```

Add a private computed property on the view:

```swift
private var shouldFireOnAppearInFixtureMode: Bool {
    // homeEmpty / homeOneCap / homeThreeCapsOneRevoked want onAppear to
    // fire so the fixture HouseholdClient gets called. homeLoading also
    // wants it to fire (the blocking listCaps keeps loading=true).
    // The enroll/oauth fixtures land on the home screen but its caps
    // list isn't visible, so onAppear is harmless. Same for fixtures
    // not on the home screen.
    return true
}
```

Justification: every home-targeting fixture *wants* onAppear to fire (it's what populates caps from the fixture client). For non-home fixtures the home view doesn't render and this code doesn't execute. So the guard is logically a no-op for the v1 fixtures — but written as a guard so we can disable specific fixtures if needed later.

(If you prefer, simplify by removing the `if FixtureRuntime.isActive` branch entirely and just always sending `.onAppear`. The guard exists because `AppView` skips its onAppear in fixture mode and we want to be consistent. Either form is fine; this plan adopts the explicit guard form for symmetry.)

- [ ] **Step 3: Build**

```bash
xcodebuild build \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -quiet
```

Expected: exit 0.

- [ ] **Step 4: Manual smoke test (one fixture)**

Boot the simulator and launch the app with a fixture, by hand:

```bash
# Boot:
xcrun simctl bootstatus 161DAE86-C4C7-47FE-B25E-1FAF251F93F6 -b

# Install + launch with fixture env:
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  build install -quiet

# Wait for install, then launch:
xcrun simctl launch \
  --terminate-running-process \
  --setenv WIRES_FIXTURE=home_one_cap \
  --setenv WIRES_APPEARANCE=light \
  161DAE86-C4C7-47FE-B25E-1FAF251F93F6 \
  io.example.wires.Wires
```

The bundle id may be different — find it with:

```bash
PLIST=$(find ~/Library/Developer/Xcode/DerivedData -name 'Wires.app' -type d 2>/dev/null | head -1)/Info.plist
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$PLIST"
```

Use that bundle id in the launch command.

Open Simulator.app to confirm the home screen renders with "Aaron's Mac" / "family" / read · write cap. If light mode shows, the appearance plumbing works.

If the fixture screen *doesn't* show, the most likely culprits are (a) HomeView's `.task` not firing onAppear, or (b) the fixture's listCaps not actually being called. Add a `print("fixture: listCaps called")` to `Fixtures+Household.swift` to verify.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/WiresApp.swift Wires/Wires/Features/Home/HomeView.swift
git commit -m "$(cat <<'EOF'
ios: WIRES_FIXTURE / WIRES_APPEARANCE launch wiring

WiresIOSApp now reads WIRES_FIXTURE on launch — when present, installs
the matching LaunchFixture before building the Store, seeds the Store's
initial state with the fixture's initialAppState, and skips
prepareWiresApp + AppFeature.onAppear (which would otherwise touch
Keychain). WIRES_APPEARANCE forces the key window's interface style.
HomeView's onAppear guard documented for symmetry with AppView.

Verified manually by launching with WIRES_FIXTURE=home_one_cap.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: SnapshotSweep XCTest class

**Files:**
- Create: `Wires/WiresUITests/SnapshotSweep.swift`

- [ ] **Step 1: Create SnapshotSweep.swift**

Content:

```swift
import XCTest

/// Snapshot sweep. One test method per LaunchFixture; each method
/// relaunches the app once per Appearance, screenshots, and writes the
/// PNG to `$WIRES_SCREENSHOT_DIR/<flow>/<short>-<appearance>.png`.
///
/// Driven by scripts/snapshot-ios.sh — when invoked from xcodebuild
/// directly, `WIRES_SCREENSHOT_DIR` defaults to a tmp dir.
final class SnapshotSweep: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = true  // collect every fixture per run
    }

    // MARK: - Test methods (one per LaunchFixture)

    func test_bootstrap_scan_denied()        throws { try snap("bootstrap_scan_denied",        flow: "bootstrap", short: "scan-denied") }
    func test_bootstrap_scan_granted()       throws { try snap("bootstrap_scan_granted",       flow: "bootstrap", short: "scan-granted") }
    func test_bootstrap_confirm()            throws { try snap("bootstrap_confirm",            flow: "bootstrap", short: "confirm") }
    func test_bootstrap_done()               throws { try snap("bootstrap_done",               flow: "bootstrap", short: "done") }

    func test_home_loading()                 throws { try snap("home_loading",                 flow: "home",     short: "loading") }
    func test_home_empty()                   throws { try snap("home_empty",                   flow: "home",     short: "empty") }
    func test_home_one_cap()                 throws { try snap("home_one_cap",                 flow: "home",     short: "one-cap") }
    func test_home_three_caps_one_revoked()  throws { try snap("home_three_caps_one_revoked",  flow: "home",     short: "three-caps-one-revoked") }

    func test_enroll_scan()                  throws { try snap("enroll_scan",                  flow: "enroll",   short: "scan") }
    func test_enroll_approve_pristine()      throws { try snap("enroll_approve_pristine",      flow: "enroll",   short: "approve-pristine") }
    func test_enroll_approve_partial()       throws { try snap("enroll_approve_partial",       flow: "enroll",   short: "approve-partial") }
    func test_enroll_done()                  throws { try snap("enroll_done",                  flow: "enroll",   short: "done") }

    func test_oauth_scan()                   throws { try snap("oauth_scan",                   flow: "oauth",    short: "scan") }
    func test_oauth_signin_confirm()         throws { try snap("oauth_signin_confirm",         flow: "oauth",    short: "signin-confirm") }
    func test_oauth_pair_approve()           throws { try snap("oauth_pair_approve",           flow: "oauth",    short: "pair-approve") }
    func test_oauth_done()                   throws { try snap("oauth_done",                   flow: "oauth",    short: "done") }
    func test_oauth_error()                  throws { try snap("oauth_error",                  flow: "oauth",    short: "error") }

    // MARK: - Helper

    private enum Appearance: String, CaseIterable {
        case light
        case dark
    }

    @MainActor
    private func snap(_ fixture: String, flow: String, short: String) throws {
        let outputRoot = ProcessInfo.processInfo.environment["WIRES_SCREENSHOT_DIR"]
            ?? NSTemporaryDirectory() + "wires-screenshots/default"
        let flowDir = URL(fileURLWithPath: outputRoot).appendingPathComponent(flow)
        try FileManager.default.createDirectory(at: flowDir, withIntermediateDirectories: true)

        for appearance in Appearance.allCases {
            let app = XCUIApplication()
            app.launchEnvironment = [
                "WIRES_FIXTURE": fixture,
                "WIRES_APPEARANCE": appearance.rawValue,
            ]
            app.launch()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10),
                          "fixture \(fixture)/\(appearance.rawValue): did not reach foreground")
            // Settle interval — empirically enough for the seeded
            // AppFeature.State to mount and the first frame to render.
            Thread.sleep(forTimeInterval: 0.6)

            let png = XCUIScreen.main.screenshot().pngRepresentation
            let url = flowDir.appendingPathComponent("\(short)-\(appearance.rawValue).png")
            try png.write(to: url)

            app.terminate()
        }
    }
}
```

- [ ] **Step 2: Replace the stub WiresUITests.swift**

The existing `Wires/WiresUITests/WiresUITests.swift` has two no-op methods. Leave it in place but skip them so the snapshot sweep runs in isolation. Replace the file contents with:

```swift
import XCTest

/// Placeholder. SnapshotSweep is the only useful UITest right now;
/// when real UITests are added they should live in a new sibling
/// target (see plan §"Deviation from spec").
final class WiresUITests: XCTestCase {
    @MainActor
    func test_placeholder() throws {
        // No-op. Existence keeps the target compilable.
    }
}
```

- [ ] **Step 3: Verify file location**

`SnapshotSweep.swift` sits at `Wires/WiresUITests/SnapshotSweep.swift`, inside the `WiresUITests` synchronized group. That alone makes it a member of the `WiresUITests` target — no pbxproj edit or Xcode UI step.

- [ ] **Step 4: Build the UI test target**

```bash
xcodebuild build-for-testing \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -only-testing:WiresUITests \
  -quiet
```

Expected: exit 0. The UITest target builds without running.

- [ ] **Step 5: Commit**

```bash
git add Wires/WiresUITests/SnapshotSweep.swift \
        Wires/WiresUITests/WiresUITests.swift
git commit -m "$(cat <<'EOF'
ios: add SnapshotSweep UITest class

17 test methods (one per LaunchFixture) each relaunch the app twice
(light/dark), wait for foreground + 600 ms settle, and write
XCUIScreen.main.screenshot().pngRepresentation directly to
$WIRES_SCREENSHOT_DIR/<flow>/<short>-<appearance>.png on the host
filesystem. The driver script in the next task supplies that env.

Stub WiresUITests reduced to a single no-op so the snapshot sweep
runs in isolation without interleaved real UI tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: scripts/snapshot-ios.sh

**Files:**
- Create: `scripts/snapshot-ios.sh`

- [ ] **Step 1: Confirm scripts/ directory exists**

```bash
ls -la /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr/scripts
```

Expected: directory exists. If not, the script will create it.

- [ ] **Step 2: Create the script**

Content of `scripts/snapshot-ios.sh`:

```bash
#!/usr/bin/env bash
#
# snapshot-ios.sh — drive the WiresUITests/SnapshotSweep matrix.
#
# Usage:
#   scripts/snapshot-ios.sh [--fixture NAME] [--device UDID]
#                           [--keep-derived]
#
# Outputs:
#   Wires/screenshots/<run-id>/<flow>/<short>-<appearance>.png
#   Wires/screenshots/latest → <run-id>      (symlink)
#
# Exit non-zero on missing screenshots or test failures.

set -euo pipefail

# ----- Resolve repo root (works from any cwd inside the repo) ---------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ----- Defaults -------------------------------------------------------
DEFAULT_UDID="161DAE86-C4C7-47FE-B25E-1FAF251F93F6"
DEVICE_UDID="$DEFAULT_UDID"
FIXTURE_FILTER=""
KEEP_DERIVED="0"

# ----- Parse flags ----------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      FIXTURE_FILTER="$2"
      shift 2
      ;;
    --device)
      DEVICE_UDID="$2"
      shift 2
      ;;
    --keep-derived)
      KEEP_DERIVED="1"
      shift
      ;;
    --help|-h)
      sed -n '2,/^$/p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 64
      ;;
  esac
done

# ----- Verify simulator exists ----------------------------------------
if ! xcrun simctl list devices | grep -q "$DEVICE_UDID"; then
  # Fall back to matching the default device by name + runtime.
  FALLBACK_UDID="$(
    xcrun simctl list devices available -j |
      python3 -c '
import json, sys
data = json.load(sys.stdin)
for runtime, devices in data["devices"].items():
    if "iOS-26" not in runtime: continue
    for d in devices:
        if d.get("name") == "iPhone 17 Pro" and d.get("isAvailable", False):
            print(d["udid"])
            sys.exit(0)
'
  )"
  if [[ -z "$FALLBACK_UDID" ]]; then
    echo "Boot iPhone 17 Pro (iOS 26.x) in Simulator.app or install the iOS 26 simulator runtime." >&2
    exit 65
  fi
  echo "Default UDID not present; using fallback iPhone 17 Pro: $FALLBACK_UDID" >&2
  DEVICE_UDID="$FALLBACK_UDID"
fi

# ----- Boot if needed -------------------------------------------------
echo "Booting simulator $DEVICE_UDID …"
xcrun simctl bootstatus "$DEVICE_UDID" -b >/dev/null

# ----- Compute run dir + export env for the UITest --------------------
RUN_ID="$(date +%Y-%m-%d-%H%M)"
RUN_DIR="$REPO_ROOT/Wires/screenshots/$RUN_ID"
mkdir -p "$RUN_DIR"
export WIRES_SCREENSHOT_DIR="$RUN_DIR"
export WIRES_RUN_ID="$RUN_ID"

# ----- Build the -only-testing argument -------------------------------
if [[ -n "$FIXTURE_FILTER" ]]; then
  # Translate fixture name (e.g. bootstrap_scan_denied) to test method name.
  ONLY_TEST="WiresUITests/SnapshotSweep/test_${FIXTURE_FILTER}"
else
  ONLY_TEST="WiresUITests/SnapshotSweep"
fi

XCRESULT="$RUN_DIR/.xcresult"
echo "Running snapshot sweep → $RUN_DIR"
set +e
xcodebuild test \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination "platform=iOS Simulator,id=$DEVICE_UDID" \
  -only-testing:"$ONLY_TEST" \
  -resultBundlePath "$XCRESULT" \
  -quiet
TEST_EXIT=$?
set -e

# ----- Write .meta.json ----------------------------------------------
APP_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
HOST_MACOS="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
SIM_RUNTIME="$(xcrun simctl list runtimes available | grep -i 'iOS' | head -1 | sed 's/^[[:space:]]*//')"
cat > "$RUN_DIR/.meta.json" <<JSON
{
  "run_id": "$RUN_ID",
  "device_udid": "$DEVICE_UDID",
  "simulator_runtime": "$SIM_RUNTIME",
  "app_commit": "$APP_COMMIT",
  "host_macos": "$HOST_MACOS",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

# ----- Refresh `latest` symlink atomically ---------------------------
cd "$REPO_ROOT/Wires/screenshots"
ln -sfn "$RUN_ID" .latest.tmp
mv -f .latest.tmp latest
cd "$REPO_ROOT"

# ----- Print manifest --------------------------------------------------
echo
echo "Manifest:"
find "$RUN_DIR" -name '*.png' -type f | sort | sed "s|^$RUN_DIR/|  |"

# ----- Clean DerivedData unless asked to keep -------------------------
if [[ "$KEEP_DERIVED" == "0" ]]; then
  rm -rf "$XCRESULT" 2>/dev/null || true
fi

# ----- Done ----------------------------------------------------------
PNG_COUNT="$(find "$RUN_DIR" -name '*.png' -type f | wc -l | tr -d ' ')"
echo
echo "Run: $RUN_ID"
echo "PNGs: $PNG_COUNT"
echo "Path: $RUN_DIR"
echo "Symlink: $REPO_ROOT/Wires/screenshots/latest"

if [[ "$TEST_EXIT" != "0" ]]; then
  echo "WARNING: xcodebuild test exited $TEST_EXIT — some fixtures may be missing." >&2
  exit "$TEST_EXIT"
fi
```

- [ ] **Step 3: Make it executable**

```bash
chmod +x /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr/scripts/snapshot-ios.sh
```

- [ ] **Step 4: Smoke test --help**

```bash
/Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr/scripts/snapshot-ios.sh --help
```

Expected: prints the header comment block. Exit 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/snapshot-ios.sh
git commit -m "$(cat <<'EOF'
scripts: snapshot-ios.sh driver for the UI snapshot sweep

Boots iPhone 17 Pro simulator (or falls back to any iOS 26 instance),
exports WIRES_SCREENSHOT_DIR=<run-id>, runs xcodebuild test against
WiresUITests/SnapshotSweep (with optional --fixture filter), writes
.meta.json with run/commit/runtime info, refreshes the `latest`
symlink atomically, and prints a manifest. Exits non-zero on test
failure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: End-to-end run + visual verification

**Files:** (no source changes — this task is verification)

- [ ] **Step 1: Boot simulator + warm xcodebuild cache**

```bash
cd /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr
xcrun simctl bootstatus 161DAE86-C4C7-47FE-B25E-1FAF251F93F6 -b
xcodebuild build-for-testing \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination 'platform=iOS Simulator,id=161DAE86-C4C7-47FE-B25E-1FAF251F93F6' \
  -only-testing:WiresUITests \
  -quiet
```

Expected: exit 0 in under ~3 minutes on a warm machine.

- [ ] **Step 2: Single-fixture dry run**

```bash
./scripts/snapshot-ios.sh --fixture home_one_cap
```

Expected: ~30 seconds. Output includes:
- "Booting simulator …" once
- "Running snapshot sweep → Wires/screenshots/2026-…"
- "Manifest:" followed by `home/one-cap-light.png` and `home/one-cap-dark.png`
- "PNGs: 2"

- [ ] **Step 3: Inspect one PNG manually**

```bash
open /Users/aaron/src/wires/.claude/worktrees/wires-mcp-single-qr/Wires/screenshots/latest/home/one-cap-light.png
```

Confirm visually:
- Home screen shows the navigation title "Household"
- Section header reads "Aaron's Mac"
- One cap row reads "family" with rights "read · write"
- Light appearance — white background, dark text

If any of these are wrong: the fixture state isn't reaching the view. Most likely cause: HomeView's onAppear ran and overwrote seeded state. Re-check Task 5 Step 2.

- [ ] **Step 4: Full sweep**

```bash
./scripts/snapshot-ios.sh
```

Expected: ~5–8 minutes. Output ends with "PNGs: 34" (17 × 2).

- [ ] **Step 5: Spot-check the manifest**

```bash
find Wires/screenshots/latest -name '*.png' | sort
```

Expected: exactly 34 paths, four under bootstrap/, eight under home/, eight under enroll/, ten under oauth/, plus the symlink. Confirm grouping is sensible.

- [ ] **Step 6: Open a contact sheet**

If `imagemagick` is available, build a quick contact sheet to eyeball everything at once:

```bash
brew list imagemagick >/dev/null 2>&1 || brew install imagemagick
montage Wires/screenshots/latest/*/*.png \
  -tile 4x \
  -geometry 300x650+8+8 \
  Wires/screenshots/latest/_contact-sheet.png
open Wires/screenshots/latest/_contact-sheet.png
```

Confirm each screen renders the intended state. Common things to look for:
- `bootstrap/scan-denied-*.png` shows the "Camera access denied" copy
- `bootstrap/scan-granted-*.png` shows the dark viewfinder placeholder + a QR reticle
- `bootstrap/confirm-*.png` shows the ConfirmHostView with a host endpoint id
- `home/loading-*.png` shows a spinner only
- `home/empty-*.png` shows "No nodes yet"
- `enroll/approve-pristine-*.png` shows the scopes form with toggles ON
- `oauth/signin-confirm-*.png` shows the "Sign in to https://wires-mcp.example.org" copy

If any fixture renders the wrong screen: open `LaunchFixture.swift`, fix the `initialAppState` arm, rerun `./scripts/snapshot-ios.sh --fixture <name>`, and reinspect. Commit the fix as its own commit (`fixture: …`).

- [ ] **Step 7: No commit unless tweaks were needed**

This task is verification. If you had to amend any fixture, commit those amendments. Otherwise skip.

---

## Task 9: gitignore + CLAUDE.md update

**Files:**
- Modify: `.gitignore`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add screenshots to .gitignore**

The current `.gitignore` is in the repo root. Verify by `cat .gitignore | head -30` to find a good insertion point — likely after the Xcode UserData section.

Add this block (avoid replace_all; insert at a clean section break):

```
# UI snapshot sweep artifacts. Curate selected runs into
# docs/ui-baselines/<date>/ to track historically.
Wires/screenshots/
```

- [ ] **Step 2: Add a one-line pointer to CLAUDE.md "Status" section**

`CLAUDE.md`'s "## Status" section has a bulleted list of shipped slices. Find the existing trailing bullet (currently the MCP single-QR consent dispatch line ending with "Spec §5 updated.") and add immediately after it:

```
- **iOS UI snapshot tooling v1** (landed 2026-05-19) — `scripts/snapshot-ios.sh` drives `WiresUITests/SnapshotSweep` to capture every notable iOS UI state as PNGs under `Wires/screenshots/<run-id>/`. 17 fixtures × light/dark on iPhone 17 Pro (iOS 26.1). Spec: `docs/superpowers/specs/2026-05-19-wires-ios-snapshot-tooling-design.md`.
```

- [ ] **Step 3: Verify nothing accidentally tracked**

```bash
git status -s
```

Expected: only `.gitignore` and `CLAUDE.md` modified, plus any other in-flight changes. Confirm there are no `Wires/screenshots/…` paths showing as untracked.

- [ ] **Step 4: Commit**

```bash
git add .gitignore CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: gitignore screenshots dir; note snapshot tooling in CLAUDE.md

Wires/screenshots/ holds run artifacts that change every sweep; track
curated baselines under docs/ui-baselines/<date>/ instead. CLAUDE.md
Status now points readers at the new harness.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist (do this after completing all tasks)

- [ ] All 17 fixture cases have non-stub `applyDependencies` AND `initialAppState` arms.
- [ ] `./scripts/snapshot-ios.sh` (no flags) exits 0 and produces exactly 34 PNGs.
- [ ] `git status` is clean (modulo `Wires/screenshots/` which is gitignored).
- [ ] The full suite of commits looks reviewable: each task should be one commit, with a message that explains *why* (not just *what*).
- [ ] The simulator UDID `161DAE86-C4C7-47FE-B25E-1FAF251F93F6` is referenced in the script and in this plan; if it changed on the host machine, `scripts/snapshot-ios.sh`'s fallback should pick up the new one automatically.
- [ ] `CameraPreviewKind.live` is the default; production launches (no `WIRES_FIXTURE` env) still use the real `AVCaptureSession`. Quick sanity: run the app from Xcode normally (▶), confirm the bootstrap scan view shows the live camera feed.
- [ ] No `WIRES_FIXTURE` leakage in production: search the codebase for `WIRES_FIXTURE` — only `WiresIOSApp.swift` and `LaunchFixture.swift` should mention it.
