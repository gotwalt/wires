# wires iOS — UI snapshot tooling design

**Status:** proposed
**Date:** 2026-05-19
**Owner:** ios

## 1. Problem

The wires iOS companion has reached enough functional surface area (bootstrap,
home, node enrollment, OAuth sign-in) that a UI/UX pass against Apple's
Human Interface Guidelines is overdue. We need a way to look at every screen
side-by-side, iterate on copy and layout, regenerate, and diff — repeatedly.

Today there is no harness. To see any screen you launch the simulator, drive
the app through whatever real-world plumbing reaches that state (pair flow
against a live host, OAuth probe against a live gateway, etc.), and eyeball
it on the simulator window. Capturing every state is slow, ordering-dependent,
and impossible to repeat exactly.

This spec defines a screenshot harness that:

- Captures every notable UI state of the app as a PNG.
- Is deterministic — re-running it with the same fixtures produces the same
  pixels (modulo timestamps in the UI).
- Doesn't depend on a live wires-host, wires-mcp gateway, or pair partner.
- Is fast enough to run repeatedly during a UI iteration loop (a single
  sweep completes in a few minutes).
- Produces files at predictable paths so Claude (this assistant) can `Read`
  them and produce critiques without further plumbing.

The tooling is the deliverable of this spec. The first UI/UX review pass
that consumes the tooling is a separate artifact authored after the
tooling lands.

## 2. Non-goals

- Snapshot-based regression tests with pixel-level baselines and PR
  diffing. That comes later, once the UI has stabilized.
- Visual diff UI / web companion. The artifacts are plain PNGs in a known
  directory; humans and Claude both read them with their normal tools.
- Capturing the multi-step flow as a single composite filmstrip. Each
  fixture is a single moment in time; the human and the assistant
  reconstruct the flow narrative across the per-state PNGs.
- Covering full device / dynamic-type / locale matrices on day one.
  v1 ships iPhone 17 Pro (iOS 26.1), default dynamic type, English. The
  harness is designed to extend along these axes later without
  re-architecting.
- Driving the real camera, pairing protocol, or HTTPS calls in fixture mode.
  Fixture mode swaps every external dependency for a deterministic stub.

## 3. Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Host Mac                                                    │
│                                                             │
│  scripts/snapshot-ios.sh                                    │
│    └─ xcodebuild test (Wires scheme, WiresSnapshotTests)    │
│         └─ WiresSnapshotTests (UITest, host process)        │
│              ├─ enumerates fixture × appearance × …         │
│              ├─ launches app with WIRES_FIXTURE=… etc.      │
│              ├─ XCUIScreen.main.screenshot()                │
│              └─ writes PNG to                               │
│                   Wires/screenshots/<run-id>/<flow>/<…>.png │
└─────────────────────────────────────────────────────────────┘
                          │ launchEnvironment
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Simulator                                                   │
│                                                             │
│  WiresIOSApp.init                                           │
│    └─ if env WIRES_FIXTURE set:                             │
│         LaunchFixture.install(named: …)                     │
│           └─ prepareDependencies { values in                │
│                values.householdClient   = .fixture(…)       │
│                values.wiresClient       = .fixture(…)       │
│                values.mcpGatewayClient  = .fixture(…)       │
│                values.cameraPermission  = .fixture(…)       │
│                values.cameraPreview     = .fixture(…)       │
│              }                                              │
│                                                             │
│  AppFeature.State initialized straight to the fixture's     │
│  target case (home / enroll / oauth / bootstrap) with sheet │
│  state seeded — no user interaction required.               │
└─────────────────────────────────────────────────────────────┘
```

Three new pieces of code in the iOS app:

- `Wires/Wires/Fixtures/` — new folder. `LaunchFixture.swift` (the enum +
  installer), `Fixtures+Household.swift`, `Fixtures+Wires.swift`,
  `Fixtures+MCPGateway.swift`, `Fixtures+Camera.swift`, plus a
  `FixtureRuntime` singleton that records the active fixture so views can
  branch.
- `WiresIOSApp.swift` — read `WIRES_FIXTURE` at launch, call
  `LaunchFixture.install(named:)` before building the Store. The Store's
  initial state is now derived from the fixture, not always `.launching`.
- `Wires/Wires/Features/Scan/ScanView.swift` — when fixture mode is active,
  render a static viewfinder placeholder instead of `CameraCaptureView`.
  Implemented via a new `CameraPreview` dependency (see §6) so the view
  itself doesn't grow a fixture branch.

One new test target: `WiresSnapshotTests`, separate from the existing
`WiresUITests` target so future real UI tests and the snapshot sweep don't
collide.

One new script: `scripts/snapshot-ios.sh`.

## 4. Fixture system

### 4.1 LaunchFixture

```swift
// Wires/Wires/Fixtures/LaunchFixture.swift

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

    func applyDependencies(to values: inout DependencyValues) { /* … */ }

    /// Constructs the AppFeature.State the fixture should land on. Called
    /// from WiresIOSApp when a fixture is active; replaces the normal
    /// `.launching` initial state and skips `prepareWiresApp`.
    var initialAppState: AppFeature.State { /* … */ }
}

enum FixtureRuntime {
    static let shared = Storage()
    final class Storage {
        var activeFixture: LaunchFixture?
        var malformedFixtureName: String?
    }
    static var isActive: Bool { shared.activeFixture != nil }
}
```

`FixtureRuntime` is consulted by `ScanView` (and any future view that
needs a fixture-mode rendering branch). Production builds set
`activeFixture = nil`; the code path is dead.

### 4.2 Per-dependency fixtures

Each `Fixtures+X.swift` adds a `static func fixture(…)` constructor to one
dependency client. These are minimal — they return canned data, never
throw, never call out. They live alongside production code, *not* under
`#if DEBUG`, because the snapshot test target builds in Debug
configuration anyway and the fixture-mode runtime check is a single
env-var read.

Examples (sketches, not final shape):

```swift
// Fixtures+Household.swift
extension HouseholdClient {
    static func fixture(
        household: Household? = nil,
        caps: [CapRecord] = [],
        topics: [TopicRecord] = []
    ) -> HouseholdClient {
        HouseholdClient(
            loadHousehold: { household },
            saveHousehold: { _ in },
            refreshHostInfo: { _,_,_,_ in },
            listTopics: { topics },
            saveTopic: { _ in },
            markTopicRegistered: { _ in },
            listCaps: { caps },
            saveCap: { _ in },
            wipeAll: { }
        )
    }
}
```

```swift
// Fixtures+Camera.swift
extension CameraPermissionClient {
    static func fixture(_ permission: CameraPermission) -> CameraPermissionClient {
        CameraPermissionClient(status: { permission })
    }
}

extension CameraPreview {
    static let fixture = CameraPreview { /* SwiftUI view: static viewfinder */ }
}
```

### 4.3 Initial AppFeature.State per fixture

For navigation-deep fixtures (`enrollApprovePartial`,
`oauthSigninConfirm`, etc.) the fixture also returns a fully-seeded
`AppFeature.State`. The app launches *directly into* the target screen.
We never drive sheet presentation through XCUITest interaction.

The pattern, sketched on `WiresIOSApp`:

```swift
@main
struct WiresIOSApp: App {
    static let store: Store<AppFeature.State, AppFeature.Action> = {
        if let raw = ProcessInfo.processInfo.environment["WIRES_FIXTURE"] {
            LaunchFixture.install(named: raw)
            let initial = LaunchFixture(rawValue: raw)?.initialAppState
                ?? .launching
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
        }
    }
}
```

When a fixture is active, `prepareWiresApp` is skipped (it does Keychain
I/O and FFI bootstrap unnecessary for screenshots).

### 4.4 Initial v1 fixture catalogue

| Fixture | Surface | Notes |
|---|---|---|
| `bootstrap_scan_denied` | BootstrapView/ScanView | camera permission denied state |
| `bootstrap_scan_granted` | BootstrapView/ScanView | camera permission granted; viewfinder placeholder |
| `bootstrap_confirm` | ConfirmHostView | canned host shown, not registering |
| `bootstrap_done` | DoneView | shows the rotating "registered" terminal state |
| `home_loading` | HomeView | spinner |
| `home_empty` | HomeView | "No nodes yet" empty state |
| `home_one_cap` | HomeView | one node, one cap, read+write rights |
| `home_three_caps_one_revoked` | HomeView | multi-node listing with a revoked cap |
| `enroll_scan` | NodeEnrollmentView | sheet on home; scan substate; viewfinder placeholder |
| `enroll_approve_pristine` | ApprovalView | scopes shown, nothing granted yet |
| `enroll_approve_partial` | ApprovalView | one scope on with read-only, one off |
| `enroll_done` | NodeEnrollmentView | "Node approved" terminal state |
| `oauth_scan` | OAuthSignInView | sheet; scan substate |
| `oauth_signin_confirm` | OAuthSignInView | returning-user confirm prompt |
| `oauth_pair_approve` | OAuthSignInView | placeholder branch (Task 14 deferral) |
| `oauth_done` | OAuthSignInView | success terminal state |
| `oauth_error` | OAuthSignInView | error terminal state |

17 fixtures. Pruning or extending this list does not require any
architectural change — it is one new enum case + one `applyDependencies`
arm + one `initialAppState` arm per fixture.

## 5. Capture matrix (v1)

| Axis | v1 values | Future axes |
|---|---|---|
| Fixture | 17 (§4.4) | grows organically |
| Appearance | `light`, `dark` | — |
| Dynamic type | default | + `XL accessibility` |
| Device | iPhone 17 Pro (iOS 26.1) | + iPhone SE (3rd gen), iPad mini |
| Locale | `en_US` | future localization audit |

= **34 screenshots per sweep** at v1.

Appearance is applied at launch: the app reads `WIRES_APPEARANCE` from
the environment when the scene comes up and calls
`UIWindow.overrideUserInterfaceStyle = .dark|.light` on its key window
before any view body runs. We relaunch the app once per appearance per
fixture (see §9) rather than toggling at runtime, which keeps each
screenshot a clean cold-start snapshot.

Dynamic type, when added, is set via
`app.launchArguments.append(contentsOf: ["-UIPreferredContentSizeCategoryName",
"UICTContentSizeCategoryAccessibilityXL"])` in the UITest. Device is
selected by the driver script (`-destination` flag).

## 6. ScanView fixture-mode camera

`ScanView` currently embeds a `CameraCaptureView`, which instantiates an
`AVCaptureSession` and starts running it on `viewWillAppear`. We can't
let that happen under fixture mode — there is no camera in the simulator,
and even if there were, we want a deterministic image.

Solution: introduce a new dependency, `CameraPreview`, that wraps the
SwiftUI rendering of the camera area. Two implementations:

- `CameraPreview.live` — wraps the current `CameraCaptureView` and
  forwards decoded payloads.
- `CameraPreview.fixture` — renders a static viewfinder placeholder
  (rounded rect with a subtle gradient and a centered
  `qrcode.viewfinder` SF Symbol). Decoded callback is never invoked.

`ScanView` consumes `@Dependency(\.cameraPreview)` and uses it for the
`.granted` branch. Production builds always get `.live`; fixture mode
swaps in `.fixture` via `prepareDependencies`. `ScanView` itself contains
no fixture-mode `if` branch — the dependency layer handles it.

This is a refactor that has independent value beyond snapshots: it
isolates the AV capture lifecycle behind a swappable seam, which makes
the view easier to preview in Xcode and easier to unit-test in the
future.

## 7. Output layout and run management

Each invocation of the sweep creates a new run directory under
`Wires/screenshots/<run-id>/`, where `<run-id>` is
`YYYY-MM-DD-HHMM`. A `latest` symlink at `Wires/screenshots/latest`
points at the most recent run.

```
Wires/screenshots/
  latest                          (symlink → 2026-05-19-1542)
  2026-05-19-1542/
    .meta.json                    {run_id, simulator_runtime, app_commit, host_macos, fixtures_run, started_at, finished_at}
    bootstrap/
      scan-denied-light.png
      scan-denied-dark.png
      scan-granted-light.png
      scan-granted-dark.png
      confirm-light.png
      confirm-dark.png
      done-light.png
      done-dark.png
    home/
      loading-light.png
      …
    enroll/
      …
    oauth/
      …
```

Filename schema: `<fixture-short>-<appearance>[-<size>][-<device>].png`.
`<fixture-short>` is the fixture's raw value with the flow prefix
stripped (e.g. `bootstrap_scan_denied` → file `bootstrap/scan-denied-light.png`).
Size and device segments are omitted when they're v1 defaults; they
appear only when we widen the matrix.

`.meta.json` is written by the test runner at the end of the sweep. It
makes runs auditable: when something looks wrong in a screenshot, we can
check whether the run was on a different simulator runtime or against a
different app commit.

**Commit policy.** The entire `Wires/screenshots/` tree is gitignored.
Tracking baselines historically is opt-in: a human can curate a
selected run into `docs/ui-baselines/<date>/` and commit it.

## 8. Driver script: scripts/snapshot-ios.sh

```
Usage: snapshot-ios.sh [--fixture name | --all] [--device id]
                       [--keep-derived]

Sweeps the iOS UI snapshot matrix.

Options:
  --fixture NAME    Run a single fixture by raw value.
                    Defaults to --all.
  --all             Run every fixture in LaunchFixture.allCases.
                    (Default.)
  --device ID       xcodebuild -destination ID. Defaults to the
                    pre-installed iPhone 17 Pro (iOS 26.1) simulator
                    (UDID 2FDEB6B7-09A0-4BAD-96E6-117086D09A8D on the
                    primary dev machine; the script falls back to
                    `xcrun simctl list devices` matching by name + runtime
                    if that UDID isn't present).
  --keep-derived    Don't delete DerivedData test bundles after the run.

Outputs:
  Wires/screenshots/<run-id>/  with PNGs grouped by flow.
  Updates Wires/screenshots/latest symlink.
  Prints a manifest of (fixture, appearance, file path) on success.
  Exits non-zero if any expected screenshot is missing.
```

Behavior:

1. Compute `run_id = date +%Y-%m-%d-%H%M`.
2. Resolve the destination simulator. Boot it if needed
   (`xcrun simctl bootstatus … -b`). If the requested device or runtime
   isn't installed, fail with a clear message: `Boot iPhone 17 Pro
   (iOS 26.1) in Simulator.app or install the iOS 26.1 simulator runtime.`
3. Export `WIRES_SCREENSHOT_DIR=Wires/screenshots/<run-id>` and
   `WIRES_RUN_ID=<run-id>`.
4. `xcodebuild test \
     -scheme Wires \
     -destination 'platform=iOS Simulator,id=<udid>' \
     -only-testing:WiresSnapshotTests \
     -resultBundlePath <tmp>/snapshots.xcresult`.
5. The UITest writes PNGs directly to `WIRES_SCREENSHOT_DIR` (the host
   filesystem, since UITests execute in the host process — no xcresult
   extraction needed).
6. After the test exits, refresh the `latest` symlink atomically
   (`ln -sfn <run-id> latest.tmp && mv -T latest.tmp latest`), print the
   manifest, and (unless `--keep-derived`) delete the resultBundle.
7. Exit non-zero if `Wires/screenshots/<run-id>` is missing any
   expected file — i.e., any of `LaunchFixture.allCases` × appearances
   that was requested by the run.

The script must be runnable from the repo root and from the worktree
root. It locates the Xcode project relative to its own path.

## 9. WiresSnapshotTests target

A new UITest target sibling to `WiresUITests`. Single file:
`Wires/WiresSnapshotTests/SnapshotSweep.swift`.

```swift
final class SnapshotSweep: XCTestCase {
    func test_bootstrap_scan_denied()        throws { try snap(.bootstrapScanDenied) }
    func test_bootstrap_scan_granted()       throws { try snap(.bootstrapScanGranted) }
    func test_bootstrap_confirm()            throws { try snap(.bootstrapConfirm) }
    func test_bootstrap_done()               throws { try snap(.bootstrapDone) }
    func test_home_loading()                 throws { try snap(.homeLoading) }
    func test_home_empty()                   throws { try snap(.homeEmpty) }
    func test_home_one_cap()                 throws { try snap(.homeOneCap) }
    func test_home_three_caps_one_revoked()  throws { try snap(.homeThreeCapsOneRevoked) }
    func test_enroll_scan()                  throws { try snap(.enrollScan) }
    func test_enroll_approve_pristine()      throws { try snap(.enrollApprovePristine) }
    func test_enroll_approve_partial()       throws { try snap(.enrollApprovePartial) }
    func test_enroll_done()                  throws { try snap(.enrollDone) }
    func test_oauth_scan()                   throws { try snap(.oauthScan) }
    func test_oauth_signin_confirm()         throws { try snap(.oauthSigninConfirm) }
    func test_oauth_pair_approve()           throws { try snap(.oauthPairApprove) }
    func test_oauth_done()                   throws { try snap(.oauthDone) }
    func test_oauth_error()                  throws { try snap(.oauthError) }

    private func snap(_ fixture: LaunchFixture) throws {
        for appearance in [Appearance.light, .dark] {
            let app = XCUIApplication()
            app.launchEnvironment = [
                "WIRES_FIXTURE": fixture.rawValue,
                "WIRES_APPEARANCE": appearance.rawValue,
                "WIRES_SCREENSHOT_DIR": ProcessInfo.processInfo.environment["WIRES_SCREENSHOT_DIR"]!,
            ]
            app.launch()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
            Thread.sleep(forTimeInterval: 0.6)
            let png = XCUIScreen.main.screenshot().pngRepresentation
            let url = outputURL(fixture: fixture, appearance: appearance)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try png.write(to: url)
            app.terminate()
        }
    }
}
```

`outputURL(fixture:appearance:)` derives the destination from
`WIRES_SCREENSHOT_DIR` plus the filename schema in §7:

```swift
private func outputURL(fixture: LaunchFixture, appearance: Appearance) -> URL {
    let root = URL(fileURLWithPath:
        ProcessInfo.processInfo.environment["WIRES_SCREENSHOT_DIR"]!)
    let (flow, short) = fixture.flowAndShortName  // e.g. ("bootstrap", "scan-denied")
    return root
        .appendingPathComponent(flow)
        .appendingPathComponent("\(short)-\(appearance.rawValue).png")
}
```

`flowAndShortName` lives on `LaunchFixture` and is a pure mapping from
the enum case — `bootstrapScanDenied` → `("bootstrap", "scan-denied")`,
`homeThreeCapsOneRevoked` → `("home", "three-caps-one-revoked")`, etc.

The 600 ms settle is a deliberate cheap constant. If a fixture becomes
visibly racy we tighten it per-fixture by polling `app.staticTexts[…]`
for an expected element before screenshotting.

The launchEnvironment is forwarded *every launch* — there is no shared
state between fixtures, and `app.terminate()` is required between
launches because launchEnvironment is read once at process start.

`Appearance` is an in-target enum (`light`/`dark`). The app reads
`WIRES_APPEARANCE` on launch and applies it via
`UIWindow.overrideUserInterfaceStyle` once the scene is created.

## 10. Error handling

| Failure | Surfaced as |
|---|---|
| Simulator runtime not installed | Driver script exits non-zero with explicit hint. |
| Unknown fixture name (env value typo) | App renders a red banner "Unknown fixture: foo"; sweep captures it. The bad fixture's test method then fails its file-existence check. |
| App crash during a fixture | xcodebuild reports the test as failed; remaining tests still run; manifest lists missing files. |
| Fixture rendered the wrong screen | Caught by human review of the manifest + PNGs. We don't add automated content assertions in v1. |
| Stale fixture state leaking between launches | Cannot happen: each fixture is its own process launch with its own `prepareDependencies` and its own `initialAppState`. |
| Race between launch and screenshot | 600 ms settle. If insufficient, switch to polling `app.staticTexts["expected text"].waitForExistence(timeout: 3)` before screenshotting. |
| Camera permission popping system alert | Cannot happen in fixture mode: `cameraPermissionClient` is replaced and `CameraPreview.fixture` does not instantiate `AVCaptureSession`. |

## 11. Testing

This is tooling, not a feature, so its test footprint is small.

- One unit test in `WiresTests` confirms `LaunchFixture(rawValue:)` round-trips
  every `allCases` raw value (catches typo regressions in the enum).
- One unit test confirms `LaunchFixture.allCases.count == fixtures listed in
  spec §4.4` (catches accidental fixture drops; updates require updating
  the test).
- The harness itself is exercised by being run, locally and by humans
  before iOS PRs.
- Smoke check the driver script in CI later (deferred — we don't run iOS
  simulator builds in CI today).

## 12. Future work

These are explicitly out of scope for v1, listed so they aren't forgotten:

- **Pixel-baseline regression mode.** After the UI stabilizes, add an
  opt-in `--check` mode that compares each PNG against a committed
  baseline under `docs/ui-baselines/` and fails the sweep on diffs.
  Likely uses `swift-snapshot-testing` for the diff engine but reuses
  this harness for the capture.
- **iPhone SE + accessibility XL coverage.** Trivially adds 3× more
  screenshots per fixture. Add when the iteration loop is fast enough to
  absorb it.
- **Light/dark side-by-side filmstrip.** A tiny `imagemagick montage`
  step in the driver script that produces one wide PNG per fixture
  showing every appearance. Nice for human review; not needed for the
  first pass.
- **Locale audit.** Add `WIRES_LOCALE` env passing to the test target,
  enumerate a few locales (Japanese, Arabic, German) once strings start
  flowing through `LocalizedStringKey`.
- **Catalog view inside the app.** A debug-only `LaunchFixture` picker
  reachable from the home screen lets a human flip through fixtures on a
  real device. Useful for demos.

## 13. Implementation outline (for the plan)

The plan will be authored separately. Rough decomposition:

1. Introduce `CameraPreview` dependency; refactor `ScanView` to consume it.
2. Add `Wires/Wires/Fixtures/` skeleton: `FixtureRuntime`, `LaunchFixture`
   enum with `applyDependencies(to:)` and `initialAppState` stubs.
3. Implement fixture dependency constructors: `HouseholdClient.fixture`,
   `WiresClient.fixture`, `MCPGatewayClient.fixture`,
   `CameraPermissionClient.fixture`, `CameraPreview.fixture`.
4. Fill in `applyDependencies` and `initialAppState` for each of the 17
   fixtures in §4.4.
5. Wire `WiresIOSApp.init` to read `WIRES_FIXTURE` and `WIRES_APPEARANCE`
   and skip `prepareWiresApp` in fixture mode.
6. Create `WiresSnapshotTests` target and `SnapshotSweep.swift`.
7. Write `scripts/snapshot-ios.sh`.
8. Run the sweep end-to-end; verify all 34 PNGs land and look correct.
9. Add the two unit tests in §11.
10. Update `CLAUDE.md` "Status" section with a one-line pointer to the
    new harness.

A separate spec ("wires iOS — UX pass 1") then consumes the harness's
output and produces a critique + change list.
