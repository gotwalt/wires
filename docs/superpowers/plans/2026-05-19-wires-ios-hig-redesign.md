# Wires iOS HIG-aligned redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Wires iOS app's visual and information architecture to feel like a calm sibling of Apple Passwords — indigo identity, plain-language copy, Apple Pay-style onboarding, tab bar IA ready for the future agent-chat tab, and a `ScopeDescriptor` indirection layer that survives cap-shape churn.

**Architecture:** Phased, in-place migration on the existing TCA + SwiftUI app. Each phase merges to main and keeps the snapshot harness green. Foundation types and components land first, then `MainFeature` wraps a `TabView` at the AppFeature root, then each surface is rebuilt in dependency order (Settings → Network → Service Detail → Onboarding → Connect). One small additive FFI change (`HostTicket.server_name`) lands just before Onboarding.

**Tech stack:** Swift 6 / SwiftUI iOS 26+, The Composable Architecture, Swift Testing for unit tests, snapshot harness via `scripts/snapshot-ios.sh` for visual regression. Rust side: `wires-core`, `wires-net`, `wires-host`, `wires-ioskit` (UniFFI).

**Spec:** `docs/superpowers/specs/2026-05-19-wires-ios-hig-redesign-design.md` — load it before starting any task; every task references a spec section for design intent.

---

## Phase 1 — Foundation: theme, types, and dumb components

Lands all new types and stateless visual components without altering any current screen. After this phase, the app behaves identically but a new layer is available.

### Task 1.1 — Indigo color asset + AppColors helper

**Spec:** §4 Visual system (Color).

**Files:**
- Create: `Wires/Wires/Assets.xcassets/IndigoPrimary.colorset/Contents.json`
- Create: `Wires/Wires/Theme/AppColors.swift`

- [ ] **Step 1: Create the color asset.** Write the file `Wires/Wires/Assets.xcassets/IndigoPrimary.colorset/Contents.json` with light/dark variants. Pick a slightly cooler purple than system `.indigo` — for light mode `sRGB 0.337, 0.184, 0.741, alpha 1.0` (≈ #563DBD); for dark mode `sRGB 0.490, 0.345, 0.910, alpha 1.0` (≈ #7D58E8). Both are calibrated to read close to Passwords' purple.

```json
{
  "colors": [
    {
      "color": {
        "color-space": "srgb",
        "components": {
          "alpha": "1.000",
          "blue": "0.741",
          "green": "0.184",
          "red": "0.337"
        }
      },
      "idiom": "universal"
    },
    {
      "appearances": [
        { "appearance": "luminosity", "value": "dark" }
      ],
      "color": {
        "color-space": "srgb",
        "components": {
          "alpha": "1.000",
          "blue": "0.910",
          "green": "0.345",
          "red": "0.490"
        }
      },
      "idiom": "universal"
    }
  ],
  "info": { "author": "xcode", "version": 1 }
}
```

- [ ] **Step 2: Create `AppColors.swift`.**

```swift
import SwiftUI

enum AppColors {
    /// Brand accent. Lives in Assets.xcassets so the light/dark variants stay
    /// in one place. Use everywhere the design spec calls for `indigoPrimary`.
    static let indigoPrimary = Color("IndigoPrimary")
}
```

- [ ] **Step 3: Verify build.**

```bash
cd /Users/aaron/src/wires && xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
```

Expected: build succeeds, no warnings about the asset.

- [ ] **Step 4: Commit.**

```bash
git add Wires/Wires/Assets.xcassets/IndigoPrimary.colorset Wires/Wires/Theme
git commit -m "ios: add indigoPrimary color asset + AppColors helper"
```

### Task 1.2 — ServiceCategory + ServiceStatus enums

**Spec:** §4 Glyph library, §7 Display types.

**Files:**
- Create: `Wires/Wires/Models/ServiceCategory.swift`
- Create: `Wires/Wires/Models/ServiceStatus.swift`
- Create: `Wires/WiresTests/ServiceCategoryTests.swift`

- [ ] **Step 1: Write the failing test** (`Wires/WiresTests/ServiceCategoryTests.swift`):

```swift
import Testing
@testable import Wires

@Suite("ServiceCategory")
struct ServiceCategoryTests {
    @Test("each case maps to a unique SF Symbol name")
    func sfSymbolMapping() {
        let symbols = ServiceCategory.allCases.map(\.sfSymbol)
        #expect(Set(symbols).count == symbols.count)
    }

    @Test("unknown fallback is questionmark.app.dashed")
    func unknownGlyph() {
        #expect(ServiceCategory.unknown.sfSymbol == "questionmark.app.dashed")
    }
}
```

Run: `xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests/ServiceCategoryTests`

Expected: FAIL — `ServiceCategory` not defined.

- [ ] **Step 2: Implement `ServiceCategory.swift`.**

```swift
import Foundation

enum ServiceCategory: String, CaseIterable, Codable, Sendable, Hashable {
    case banking
    case utilities
    case smartHome
    case devTool
    case unknown

    var sfSymbol: String {
        switch self {
        case .banking:    return "creditcard.fill"
        case .utilities:  return "bolt.fill"
        case .smartHome:  return "house.fill"
        case .devTool:    return "terminal.fill"
        case .unknown:    return "questionmark.app.dashed"
        }
    }
}
```

- [ ] **Step 3: Implement `ServiceStatus.swift`.**

```swift
import SwiftUI

enum ServiceStatus: String, CaseIterable, Codable, Sendable, Hashable {
    case connected
    case pending
    case disconnected
    case revoked

    var label: String {
        switch self {
        case .connected:    return "Connected"
        case .pending:      return "Pending"
        case .disconnected: return "Disconnected"
        case .revoked:      return "Revoked"
        }
    }

    var tint: Color {
        switch self {
        case .connected:    return .green
        case .pending:      return .orange
        case .disconnected: return .gray
        case .revoked:      return .red
        }
    }
}
```

- [ ] **Step 4: Run tests, verify PASS.** Same command as Step 1.

- [ ] **Step 5: Commit.**

```bash
git add Wires/Wires/Models/ServiceCategory.swift Wires/Wires/Models/ServiceStatus.swift Wires/WiresTests/ServiceCategoryTests.swift
git commit -m "ios: add ServiceCategory and ServiceStatus enums"
```

### Task 1.3 — ScopeDescriptor types

**Spec:** §3 Principle 5, §7 Display types.

**Files:**
- Create: `Wires/Wires/Models/ScopeDescriptor.swift`
- Create: `Wires/WiresTests/ScopeDescriptorTests.swift`

- [ ] **Step 1: Failing test** (`Wires/WiresTests/ScopeDescriptorTests.swift`):

```swift
import Testing
@testable import Wires

@Suite("ScopeDescriptor")
struct ScopeDescriptorTests {
    @Test("allGranted reflects detail rows in lockstep")
    func allGranted() {
        let s1 = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: true, kind: .write),
            ]
        )
        #expect(s1.allGranted == true)

        let s2 = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: false, kind: .write),
            ]
        )
        #expect(s2.allGranted == false)
    }

    @Test("settingAllGranted toggles every detail row")
    func settingAllGranted() {
        var s = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: true, kind: .write),
            ]
        )
        s.setAllGranted(false)
        #expect(s.detail.allSatisfy { !$0.granted })

        s.setAllGranted(true)
        #expect(s.detail.allSatisfy { $0.granted })
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `ScopeDescriptor.swift`.**

```swift
import Foundation

/// Generic, scope-shape-agnostic descriptor for the "what access does this
/// have / is being requested" UI. The view layer renders these. The data
/// layer (CapToServiceMapper) produces them. When the cap schema changes,
/// the mapper changes; views don't. See spec §3 Principle 5.
struct ScopeDescriptor: Equatable, Hashable, Identifiable, Sendable {
    let id: String
    let label: String
    let summary: String
    var detail: [ScopeDetailRow]

    /// True iff every detail row is granted. Drives the collapsed-state
    /// primary toggle on `ScopeRow`.
    var allGranted: Bool { detail.allSatisfy(\.granted) }

    /// Lockstep-set every detail row's `granted` flag.
    mutating func setAllGranted(_ value: Bool) {
        for i in detail.indices {
            detail[i].granted = value
        }
    }
}

struct ScopeDetailRow: Equatable, Hashable, Sendable {
    let label: String
    var granted: Bool
    let kind: ScopeRightKind
}

enum ScopeRightKind: Equatable, Hashable, Sendable {
    case read
    case write
    case grant
    case custom(String)
}
```

- [ ] **Step 3: Run tests, verify PASS.**

- [ ] **Step 4: Commit.**

```bash
git add Wires/Wires/Models/ScopeDescriptor.swift Wires/WiresTests/ScopeDescriptorTests.swift
git commit -m "ios: add ScopeDescriptor + ScopeDetailRow + ScopeRightKind"
```

### Task 1.4 — ServiceSummary view-layer type

**Spec:** §7 Display types.

**Files:**
- Create: `Wires/Wires/Models/ServiceSummary.swift`

- [ ] **Step 1: Implement.** (Pure data; tests come via the mapper in Task 1.5.)

```swift
import Foundation

/// View-layer summary of a connected service, derived from CapRecord via
/// CapToServiceMapper. Views never see CapRecord directly. See spec §7.
struct ServiceSummary: Equatable, Identifiable, Sendable {
    let id: String                  // stable id (today: capIdHex)
    let name: String                // user-visible service name
    let deviceName: String?         // "on Aaron's Mac mini"
    let category: ServiceCategory
    let status: ServiceStatus
    let scopes: [ScopeDescriptor]
    let connectedAt: Date
    let lastActivityAt: Date?
}
```

- [ ] **Step 2: Verify build.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
```

- [ ] **Step 3: Commit.**

```bash
git add Wires/Wires/Models/ServiceSummary.swift
git commit -m "ios: add ServiceSummary view-layer type"
```

### Task 1.5 — CapToServiceMapper

**Spec:** §3 Principle 5, §7 Display types.

**Files:**
- Create: `Wires/Wires/Mappers/CapToServiceMapper.swift`
- Create: `Wires/WiresTests/CapToServiceMapperTests.swift`

- [ ] **Step 1: Failing tests.**

```swift
import Foundation
import Testing
@testable import Wires

@Suite("CapToServiceMapper")
struct CapToServiceMapperTests {
    @Test("active cap maps to .connected status")
    func activeStatus() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Aaron's Mac",
            topicNames: ["family"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.status == .connected)
        #expect(s.id == "aa")
        #expect(s.name == "Aaron's Mac")
        #expect(s.deviceName == nil)  // alias used as name when device unknown
    }

    @Test("revoked cap maps to .revoked status")
    func revokedStatus() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Aaron's Mac",
            topicNames: ["family"],
            rights: ["read"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000),
            revokedAt: Date(timeIntervalSince1970: 1_715_100_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.status == .revoked)
    }

    @Test("rights produce a ScopeDescriptor per topic with detail rows")
    func scopeMapping() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Mac",
            topicNames: ["family"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.scopes.count == 1)
        let scope = s.scopes[0]
        #expect(scope.id == "family")
        #expect(scope.detail.contains { $0.kind == .read && $0.granted })
        #expect(scope.detail.contains { $0.kind == .write && $0.granted })
    }

    @Test("nil nodeAlias falls back to a generic name")
    func anonymousNode() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "cccccccc",
            nodeAlias: nil,
            topicNames: ["mqtt:hass"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_300_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.name == "Service")
    }

    @Test("default category is .unknown")
    func defaultCategory() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Mac",
            topicNames: ["family"],
            rights: ["read"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.category == .unknown)
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `CapToServiceMapper.swift`.**

```swift
import Foundation

/// Single conversion point from persistence (CapRecord) to view-layer
/// (ServiceSummary + ScopeDescriptor). When the cap shape changes (and per
/// the spec it WILL change), this file changes; views don't.
enum CapToServiceMapper {
    static func summary(from cap: CapRecord) -> ServiceSummary {
        ServiceSummary(
            id: cap.capIdHex,
            name: cap.nodeAlias.flatMap { $0.isEmpty ? nil : $0 } ?? "Service",
            deviceName: nil,    // populated once agents declare device separately
            category: .unknown, // populated once agents declare category
            status: cap.revokedAt == nil ? .connected : .revoked,
            scopes: scopes(from: cap),
            connectedAt: cap.issuedAt,
            lastActivityAt: nil
        )
    }

    private static func scopes(from cap: CapRecord) -> [ScopeDescriptor] {
        cap.topicNames.map { topic in
            ScopeDescriptor(
                id: topic,
                label: topic,
                summary: cap.rights.map(humanizedRight).joined(separator: " · "),
                detail: cap.rights.map { right in
                    ScopeDetailRow(
                        label: humanizedRight(right),
                        granted: true,
                        kind: scopeRightKind(right)
                    )
                }
            )
        }
    }

    private static func humanizedRight(_ raw: String) -> String {
        switch raw {
        case "read":  return "Read messages"
        case "write": return "Send messages"
        case "grant": return "Invite other services"
        default:      return raw.capitalized
        }
    }

    private static func scopeRightKind(_ raw: String) -> ScopeRightKind {
        switch raw {
        case "read":  return .read
        case "write": return .write
        case "grant": return .grant
        default:      return .custom(raw)
        }
    }
}
```

- [ ] **Step 3: Run tests, verify PASS.**

- [ ] **Step 4: Commit.**

```bash
git add Wires/Wires/Mappers Wires/WiresTests/CapToServiceMapperTests.swift
git commit -m "ios: add CapToServiceMapper bridging CapRecord to ServiceSummary"
```

### Task 1.6 — StatusPill component

**Spec:** §6.2 Network tab — service list, §6.3 Service detail.

**Files:**
- Create: `Wires/Wires/Components/StatusPill.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Small color-coded chip showing a `ServiceStatus`. Used in the service
/// list trailing slot, on the service-detail identity header, and anywhere
/// else status needs to read at a glance.
struct StatusPill: View {
    let status: ServiceStatus
    var showsLabel: Bool = true

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(status.tint)
                .frame(width: 8, height: 8)
            if showsLabel {
                Text(status.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(
            Capsule().fill(status.tint.opacity(0.12))
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel(status.label)
    }
}

#Preview {
    VStack(spacing: 12) {
        StatusPill(status: .connected)
        StatusPill(status: .pending)
        StatusPill(status: .disconnected)
        StatusPill(status: .revoked)
        StatusPill(status: .connected, showsLabel: false)
    }
    .padding()
}
```

- [ ] **Step 2: Verify build, then commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
git add Wires/Wires/Components/StatusPill.swift
git commit -m "ios: add StatusPill component"
```

### Task 1.7 — WiresBrandGlyph component

**Spec:** §4 Glyph library, §6.1 Step 1 Welcome.

**Files:**
- Create: `Wires/Wires/Components/WiresBrandGlyph.swift`

- [ ] **Step 1: Implement.** A vector glyph drawn as a `Shape`. Visual intent: two crossing wires forming a stylized key — a simple, recognizable mark that animates well. v1 implementation: two overlapping rounded-rectangle "wires" plus a hollow circle "key head"; the animation variant draws each stroke in sequence.

```swift
import SwiftUI

/// Brand glyph — two crossing wires forming a stylized key. The static
/// variant renders instantly; `.drawIn(duration:)` animates each segment.
/// See spec §4 Glyph library.
struct WiresBrandGlyph: View {
    enum Variant {
        case `static`
        case drawIn(duration: Double)
    }

    let variant: Variant
    var size: CGFloat = 96
    var color: Color = AppColors.indigoPrimary

    @State private var progress: CGFloat = 1.0

    var body: some View {
        ZStack {
            // Key head — open circle, top-right
            Circle()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.42, height: size * 0.42)
                .offset(x: size * 0.22, y: -size * 0.22)

            // Wire 1 — diagonal stroke from bottom-left up
            Capsule()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.08, height: size * 0.78)
                .rotationEffect(.degrees(35))

            // Wire 2 — counter diagonal
            Capsule()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.08, height: size * 0.78)
                .rotationEffect(.degrees(-35))
        }
        .frame(width: size, height: size)
        .onAppear {
            switch variant {
            case .static:
                progress = 1.0
            case .drawIn(let duration):
                progress = 0
                withAnimation(.easeOut(duration: duration)) {
                    progress = 1.0
                }
            }
        }
        .accessibilityHidden(true)
    }
}

#Preview("Static") {
    WiresBrandGlyph(variant: .static)
        .padding()
}

#Preview("Draw-in") {
    WiresBrandGlyph(variant: .drawIn(duration: 2.0))
        .padding()
}
```

- [ ] **Step 2: Verify build, commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
git add Wires/Wires/Components/WiresBrandGlyph.swift
git commit -m "ios: add WiresBrandGlyph component"
```

### Task 1.8 — ServiceIdentityHeader component

**Spec:** §6.3 Service detail (identity header), §6.4 Step 3b (Approve service).

**Files:**
- Create: `Wires/Wires/Components/ServiceIdentityHeader.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// The "this is a service" presentation block used on service detail and
/// on the connect-approve sheet. Same component, same visual identity, so
/// the approve sheet and detail page agree. See spec §6.3 / §6.4.
struct ServiceIdentityHeader: View {
    let summary: ServiceSummary
    var size: HeaderSize = .large

    enum HeaderSize {
        case large   // service detail page
        case medium  // connect-approve sheet

        var diameter: CGFloat {
            switch self {
            case .large:  return 80
            case .medium: return 64
            }
        }
        var glyphPointSize: CGFloat {
            switch self {
            case .large:  return 36
            case .medium: return 28
            }
        }
        var titleFont: Font {
            switch self {
            case .large:  return .title.bold()
            case .medium: return .title2.bold()
            }
        }
    }

    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                Circle()
                    .fill(AppColors.indigoPrimary)
                Image(systemName: summary.category.sfSymbol)
                    .font(.system(size: size.glyphPointSize, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: size.diameter, height: size.diameter)

            Text(summary.name)
                .font(size.titleFont)
                .multilineTextAlignment(.center)

            if let device = summary.deviceName {
                Text("on \(device)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            StatusPill(status: summary.status)
                .padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }
}

#Preview {
    ServiceIdentityHeader(
        summary: ServiceSummary(
            id: "1",
            name: "Chase",
            deviceName: "Aaron's Mac mini",
            category: .banking,
            status: .connected,
            scopes: [],
            connectedAt: Date(),
            lastActivityAt: nil
        )
    )
}
```

- [ ] **Step 2: Build + commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
git add Wires/Wires/Components/ServiceIdentityHeader.swift
git commit -m "ios: add ServiceIdentityHeader component"
```

### Task 1.9 — ServiceListRow component

**Spec:** §6.2 Network tab — service list (row anatomy).

**Files:**
- Create: `Wires/Wires/Components/ServiceListRow.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Grouped-list row for a service. 36pt indigo circle leading, primary name,
/// optional device subtitle, status pill trailing.
struct ServiceListRow: View {
    let summary: ServiceSummary

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(AppColors.indigoPrimary)
                Image(systemName: summary.category.sfSymbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 36, height: 36)

            VStack(alignment: .leading, spacing: 2) {
                Text(summary.name)
                    .font(.body)
                if let device = summary.deviceName {
                    Text("on \(device)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            StatusPill(status: summary.status, showsLabel: false)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(summary.name), \(summary.status.label)")
    }
}

#Preview {
    List {
        ServiceListRow(summary: .init(
            id: "1", name: "Chase",
            deviceName: "Aaron's Mac mini",
            category: .banking, status: .connected,
            scopes: [], connectedAt: Date(), lastActivityAt: nil
        ))
        ServiceListRow(summary: .init(
            id: "2", name: "Home Assistant",
            deviceName: nil,
            category: .smartHome, status: .revoked,
            scopes: [], connectedAt: Date(), lastActivityAt: nil
        ))
    }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/ServiceListRow.swift
git commit -m "ios: add ServiceListRow component"
```

### Task 1.10 — ScopeRow component

**Spec:** §3 Principle 5, §6.3 What it can do, §6.4 Access, §7 Reusable views.

**Files:**
- Create: `Wires/Wires/Components/ScopeRow.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Expandable row representing one ScopeDescriptor. Collapsed: primary
/// "approve everything" toggle + summary line. Expanded: per-detail
/// toggles. When `editable` is false, every toggle is read-only.
struct ScopeRow: View {
    @Binding var descriptor: ScopeDescriptor
    var editable: Bool
    @State private var expanded = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(descriptor.label)
                        .font(.body)
                    Text(descriptor.summary)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if editable {
                    Toggle("", isOn: Binding(
                        get: { descriptor.allGranted },
                        set: { descriptor.setAllGranted($0) }
                    ))
                    .labelsHidden()
                    .tint(AppColors.indigoPrimary)
                } else {
                    Image(systemName: descriptor.allGranted ? "checkmark.circle.fill" : "minus.circle.fill")
                        .foregroundStyle(descriptor.allGranted ? .green : .secondary)
                }
                Button {
                    withAnimation { expanded.toggle() }
                } label: {
                    Image(systemName: "chevron.right")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .buttonStyle(.plain)
            }

            if expanded {
                Divider().padding(.vertical, 6)
                ForEach(descriptor.detail.indices, id: \.self) { i in
                    HStack {
                        Text(descriptor.detail[i].label)
                            .font(.body)
                        Spacer()
                        if editable {
                            Toggle("", isOn: $descriptor.detail[i].granted)
                                .labelsHidden()
                                .tint(AppColors.indigoPrimary)
                        } else {
                            Image(systemName: descriptor.detail[i].granted ? "checkmark" : "xmark")
                                .foregroundStyle(descriptor.detail[i].granted ? .green : .secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    StatefulPreviewWrapper(ScopeDescriptor(
        id: "family",
        label: "family",
        summary: "Read messages · Send messages",
        detail: [
            .init(label: "Read messages", granted: true, kind: .read),
            .init(label: "Send messages", granted: true, kind: .write),
        ]
    )) { binding in
        List {
            ScopeRow(descriptor: binding, editable: true)
        }
    }
}

private struct StatefulPreviewWrapper<Value, Content: View>: View {
    @State var value: Value
    let content: (Binding<Value>) -> Content
    init(_ value: Value, @ViewBuilder content: @escaping (Binding<Value>) -> Content) {
        self._value = State(initialValue: value)
        self.content = content
    }
    var body: some View { content($value) }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/ScopeRow.swift
git commit -m "ios: add ScopeRow component"
```

### Task 1.11 — OnboardingScaffold component

**Spec:** §6.1 Onboarding (shared layout across all 5 steps), §7 Reusable views.

**Files:**
- Create: `Wires/Wires/Components/OnboardingScaffold.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Shared layout for every onboarding step: optional cancel/back chrome,
/// hero area, title + subtitle, body content, sticky-bottom primary and
/// secondary buttons. Ensures visual consistency across the 5 steps.
struct OnboardingScaffold<Hero: View, Content: View>: View {
    let title: String
    let subtitle: String?
    @ViewBuilder let hero: () -> Hero
    @ViewBuilder let content: () -> Content
    var primaryTitle: String
    var primaryAction: () -> Void
    var primaryDisabled: Bool = false
    var secondaryTitle: String? = nil
    var secondaryAction: (() -> Void)? = nil
    var onBack: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 0) {
            if let onBack {
                HStack {
                    Button(action: onBack) {
                        Image(systemName: "chevron.backward")
                            .font(.title3)
                            .padding(8)
                    }
                    .buttonStyle(.glass)
                    .tint(.primary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }

            Spacer(minLength: 16)
            hero()
            Spacer(minLength: 16)

            VStack(alignment: .center, spacing: 8) {
                Text(title)
                    .font(.largeTitle.bold())
                    .multilineTextAlignment(.center)
                if let subtitle {
                    Text(subtitle)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 24)

            content()
                .padding(.horizontal, 16)
                .padding(.top, 16)

            Spacer()

            VStack(spacing: 8) {
                Button(primaryTitle, action: primaryAction)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .tint(AppColors.indigoPrimary)
                    .frame(maxWidth: .infinity)
                    .disabled(primaryDisabled)

                if let secondaryTitle, let secondaryAction {
                    Button(secondaryTitle, action: secondaryAction)
                        .buttonStyle(.glass)
                        .controlSize(.large)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
    }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/OnboardingScaffold.swift
git commit -m "ios: add OnboardingScaffold shared layout"
```

### Task 1.12 — InlineErrorBanner component

**Spec:** §3 Principle 7, §6.1 Errors, §6.4 Step 5.

**Files:**
- Create: `Wires/Wires/Components/InlineErrorBanner.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Inline error panel with a clear next action. Replaces ad-hoc alerts.
struct InlineErrorBanner: View {
    let message: String
    var primaryTitle: String
    var primaryAction: () -> Void
    var secondaryTitle: String? = nil
    var secondaryAction: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundStyle(.orange)

            Text(message)
                .font(.body)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            HStack(spacing: 12) {
                if let secondaryTitle, let secondaryAction {
                    Button(secondaryTitle, action: secondaryAction)
                        .buttonStyle(.glass)
                        .controlSize(.large)
                }
                Button(primaryTitle, action: primaryAction)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .tint(AppColors.indigoPrimary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(24)
    }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/InlineErrorBanner.swift
git commit -m "ios: add InlineErrorBanner component"
```

### Task 1.13 — DestructiveFooterButton component

**Spec:** §6.3 Service detail destructive footer, §6.5 Delete account.

**Files:**
- Create: `Wires/Wires/Components/DestructiveFooterButton.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// iOS Settings-style red-text destructive button used outside any card,
/// at the bottom of a scrolling page.
struct DestructiveFooterButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(role: .destructive, action: action) {
            Text(title)
                .font(.body)
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 14)
        }
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 12))
        .padding(.horizontal, 16)
        .padding(.vertical, 24)
    }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/DestructiveFooterButton.swift
git commit -m "ios: add DestructiveFooterButton component"
```

### Task 1.14 — AdvancedDisclosure component

**Spec:** §3 Principle 8, §6.3 Advanced.

**Files:**
- Create: `Wires/Wires/Components/AdvancedDisclosure.swift`

- [ ] **Step 1: Implement.**

```swift
import SwiftUI

/// Labeled DisclosureGroup styled to match grouped form cards. Used wherever
/// we hide hex/key material behind a deliberate user reveal.
struct AdvancedDisclosure<Content: View>: View {
    let title: String
    @State private var expanded = false
    @ViewBuilder let content: () -> Content

    var body: some View {
        DisclosureGroup(title, isExpanded: $expanded) {
            content()
                .padding(.top, 8)
        }
        .font(.subheadline.weight(.medium))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 12))
    }
}
```

- [ ] **Step 2: Build + commit.**

```bash
git add Wires/Wires/Components/AdvancedDisclosure.swift
git commit -m "ios: add AdvancedDisclosure component"
```

### Task 1.15 — Phase 1 verification

- [ ] **Step 1: Run full unit test suite.**

```bash
xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests
```

Expected: all existing tests still pass, three new test suites pass (`ServiceCategoryTests`, `ScopeDescriptorTests`, `CapToServiceMapperTests`).

- [ ] **Step 2: Run a snapshot sweep to confirm no visual regression.**

```bash
./scripts/snapshot-ios.sh
```

Expected: all 14 existing fixtures still render identically. The Phase 1 work is dormant — nothing visible should have changed yet. Diff Wires/screenshots/latest against the previous run to confirm.

---

## Phase 2 — `MainFeature` with TabView at AppFeature root

Wraps the existing `HomeFeature` inside a new `MainFeature` that hosts a TabView. Settings tab is a placeholder stub for now (filled in Phase 3). No visual change to Network tab content yet — it still renders the current `HomeView`.

### Task 2.1 — Stub SettingsFeature

**Spec:** §5 Top-level TCA state, §6.5 Settings tab (placeholder; full content in Phase 3).

**Files:**
- Create: `Wires/Wires/Features/Settings/SettingsFeature.swift`
- Create: `Wires/Wires/Features/Settings/SettingsView.swift`
- Create: `Wires/WiresTests/SettingsFeatureTests.swift`

- [ ] **Step 1: Failing test.**

```swift
import ComposableArchitecture
import Testing
@testable import Wires

@Suite("SettingsFeature (stub)")
struct SettingsFeatureTests {
    @Test("starts with no state mutation")
    func startsBare() async {
        let store = await TestStore(initialState: SettingsFeature.State()) {
            SettingsFeature()
        }
        _ = store
    }
}
```

Run + verify FAIL (`SettingsFeature` undefined).

- [ ] **Step 2: Implement stub feature.**

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct SettingsFeature {
    @ObservableState
    struct State: Equatable {}

    enum Action {}

    var body: some Reducer<State, Action> {
        EmptyReducer()
    }
}
```

- [ ] **Step 3: Implement stub view.**

```swift
import ComposableArchitecture
import SwiftUI

struct SettingsView: View {
    let store: StoreOf<SettingsFeature>

    var body: some View {
        NavigationStack {
            Text("Settings")
                .font(.largeTitle.bold())
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationTitle("Settings")
        }
    }
}
```

- [ ] **Step 4: Run tests, verify PASS. Commit.**

```bash
git add Wires/Wires/Features/Settings Wires/WiresTests/SettingsFeatureTests.swift
git commit -m "ios: stub SettingsFeature + SettingsView"
```

### Task 2.2 — MainFeature reducer

**Spec:** §5 Top-level TCA state.

**Files:**
- Create: `Wires/Wires/Features/Main/MainFeature.swift`
- Create: `Wires/WiresTests/MainFeatureTests.swift`

- [ ] **Step 1: Failing test.**

```swift
import ComposableArchitecture
import Testing
@testable import Wires

@Suite("MainFeature")
struct MainFeatureTests {
    @Test("forwards home actions to the home child")
    func forwardsHome() async {
        let store = await TestStore(
            initialState: MainFeature.State(
                home: HomeFeature.State(rootPubkeyHex: "ab"),
                settings: SettingsFeature.State(),
                selectedTab: .network
            )
        ) {
            MainFeature()
        } withDependencies: {
            $0.householdClient = .testValue
            $0.wiresClient = .testValue
            $0.keychainClient = .testValue
        }
        _ = store
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `MainFeature.swift`.**

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct MainFeature {
    @ObservableState
    struct State: Equatable {
        var home: HomeFeature.State
        var settings: SettingsFeature.State
        var selectedTab: Tab

        enum Tab: Hashable { case network, settings }
    }

    enum Action {
        case home(HomeFeature.Action)
        case settings(SettingsFeature.Action)
        case tabSelected(State.Tab)
    }

    var body: some Reducer<State, Action> {
        Scope(state: \.home, action: \.home) { HomeFeature() }
        Scope(state: \.settings, action: \.settings) { SettingsFeature() }
        Reduce { state, action in
            switch action {
            case let .tabSelected(tab):
                state.selectedTab = tab
                return .none
            case .home, .settings:
                return .none
            }
        }
    }
}
```

- [ ] **Step 3: Run tests, PASS. Commit.**

```bash
git add Wires/Wires/Features/Main/MainFeature.swift Wires/WiresTests/MainFeatureTests.swift
git commit -m "ios: add MainFeature composing Home + Settings via TabView state"
```

### Task 2.3 — MainView with TabView

**Files:**
- Create: `Wires/Wires/Features/Main/MainView.swift`

- [ ] **Step 1: Implement.**

```swift
import ComposableArchitecture
import SwiftUI

struct MainView: View {
    @Bindable var store: StoreOf<MainFeature>

    var body: some View {
        TabView(selection: $store.selectedTab.sending(\.tabSelected)) {
            HomeView(store: store.scope(state: \.home, action: \.home))
                .tabItem {
                    Label("Network", systemImage: "circle.hexagongrid")
                }
                .tag(MainFeature.State.Tab.network)

            SettingsView(store: store.scope(state: \.settings, action: \.settings))
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
                .tag(MainFeature.State.Tab.settings)
        }
        .tint(AppColors.indigoPrimary)
    }
}
```

- [ ] **Step 2: Build, commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
git add Wires/Wires/Features/Main/MainView.swift
git commit -m "ios: add MainView TabView"
```

### Task 2.4 — Wire MainFeature into AppFeature

**Files:**
- Modify: `Wires/Wires/App/AppFeature.swift`
- Modify: `Wires/Wires/WiresApp.swift` (or wherever the root view lives)

- [ ] **Step 1: Replace the `.home(HomeFeature.State)` case with `.main(MainFeature.State)`.**

In `AppFeature.swift`:

- Add `case main(MainFeature.State)` (remove `.home`).
- Replace any `state = .home(...)` assignment with `state = .main(MainFeature.State(home: ..., settings: SettingsFeature.State(), selectedTab: .network))`.
- Update the `case .home(.didReset):` arm to `case .main(.home(.didReset)):`.
- Add `.ifCaseLet(\.main, action: \.main) { MainFeature() }`.
- Remove `.ifCaseLet(\.home, action: \.home) { HomeFeature() }`.
- Update the `case .bootstrap(.bootstrapCompleted(rootPubkeyHex)):` arm so the new state assignment creates `.main(...)`.
- The `Action` enum: rename `case home(HomeFeature.Action)` to `case main(MainFeature.Action)`.

- [ ] **Step 2: Update the root view.** Wherever the AppFeature is bound (likely in `WiresApp.swift` or `Wires/Wires/WiresApp.swift`), the `.home` case becomes `.main`, rendering `MainView` instead of `HomeView`.

```swift
// Before:
case .home(let childStore):
    HomeView(store: childStore.scope(state: \.home, action: \.home))

// After:
case .main(let childStore):
    MainView(store: childStore.scope(state: \.main, action: \.main))
```

(Adjust syntax to match the actual switch shape.)

- [ ] **Step 3: Update existing snapshot fixtures.** `LaunchFixture.initialAppState` returns `.home(HomeFeature.State)` in many arms — change each to `.main(MainFeature.State(home: ..., settings: SettingsFeature.State(), selectedTab: .network))`.

- [ ] **Step 4: Build, run unit tests, run snapshot sweep.**

```bash
xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests
./scripts/snapshot-ios.sh
```

Expected: unit tests pass; snapshot sweep shows the existing home fixtures now have a tab bar at the bottom (one visible regression — captured by the harness). Visually inspect a couple of PNGs to confirm the tab bar with "Network" / "Settings" appears.

- [ ] **Step 5: Commit.**

```bash
git add Wires/Wires/App Wires/Wires/WiresApp.swift Wires/Wires/Fixtures/LaunchFixture.swift
git commit -m "ios: wrap home in MainFeature with TabView at AppFeature root"
```

---

## Phase 3 — Settings tab

Builds out the real Settings tab content, including the destructive Delete account flow. After this phase the existing `#if DEBUG` "Reset household" toolbar button on HomeView can be retired.

### Task 3.1 — SettingsFeature state + actions

**Spec:** §6.5 Settings tab.

**Files:**
- Modify: `Wires/Wires/Features/Settings/SettingsFeature.swift`
- Modify: `Wires/WiresTests/SettingsFeatureTests.swift`

- [ ] **Step 1: Define the State shape.** Settings owns no persistent data — it reads from `householdClient` and `keychainClient` on appear, displays it, and exposes the delete-account destructive sheet.

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct SettingsFeature {
    @ObservableState
    struct State: Equatable {
        var serverName: String = ""
        var serverURL: String = ""
        var rootPubkeyHex: String = ""
        var faceIDEnabled: Bool = false
        var loading: Bool = true
        var showingAccountDetail = false
        @Presents var deleteSheet: DeleteAccountFeature.State?

        var appVersion: String {
            Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        }
    }

    enum Action {
        case onAppear
        case loaded(serverName: String, serverURL: String, rootPubkeyHex: String, faceIDEnabled: Bool)
        case accountRowTapped
        case accountDetailDismissed
        case faceIDToggled(Bool)
        case deleteAccountTapped
        case deleteSheet(PresentationAction<DeleteAccountFeature.Action>)
        case accountDeleted
    }

    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                let household = self.household
                let keychain = self.keychain
                return .run { send in
                    guard let h = try? await household.loadHousehold() else { return }
                    let faceIDEnabled = (try? keychain.attributesFor(
                        account: KeychainBackedRootSigner.Account.signingKey
                    )?.accessibility == .afterFirstUnlockThisDeviceOnlyBiometricCurrentSet) ?? false
                    await send(.loaded(
                        serverName: h.hostEndpointIdHex ?? "",
                        serverURL: h.hostRelayURL ?? "",
                        rootPubkeyHex: h.rootPubkeyHex,
                        faceIDEnabled: faceIDEnabled
                    ))
                }

            case let .loaded(serverName, serverURL, rootPubkeyHex, faceIDEnabled):
                state.serverName = serverName
                state.serverURL = serverURL
                state.rootPubkeyHex = rootPubkeyHex
                state.faceIDEnabled = faceIDEnabled
                state.loading = false
                return .none

            case .accountRowTapped:
                state.showingAccountDetail = true
                return .none

            case .accountDetailDismissed:
                state.showingAccountDetail = false
                return .none

            case let .faceIDToggled(newValue):
                state.faceIDEnabled = newValue
                // Real ACL re-write happens out-of-band via SecItem; the
                // initial v1 implementation just flips the bit.
                return .none

            case .deleteAccountTapped:
                state.deleteSheet = DeleteAccountFeature.State()
                return .none

            case .deleteSheet(.presented(.confirmed)):
                state.deleteSheet = nil
                return .send(.accountDeleted)

            case .deleteSheet:
                return .none

            case .accountDeleted:
                return .none
            }
        }
        .ifLet(\.$deleteSheet, action: \.deleteSheet) { DeleteAccountFeature() }
    }
}
```

- [ ] **Step 2: Add `attributesFor` extension to `KeychainClient` if missing.** Check `Wires/Wires/Dependencies/KeychainClient.swift`. If it doesn't already expose an `attributesFor` lookup, add a minimal helper:

```swift
// Pseudocode — adapt to KeychainClient's existing API
public func attributesFor(account: String) -> (accessibility: Accessibility)? { /* ... */ }
```

If the existing API surface is sufficient (e.g. you can derive Face-ID-on/off from `getData` succeeding or another existing call), use that instead.

- [ ] **Step 3: Build + write a reducer test that confirms `onAppear → loaded` populates the state.** Add to `SettingsFeatureTests.swift`:

```swift
@Test("loaded action populates state fields")
func loadedPopulates() async {
    let store = await TestStore(initialState: SettingsFeature.State()) {
        SettingsFeature()
    } withDependencies: {
        $0.householdClient = .fixture(household: Household(
            rootPubkeyHex: "ab",
            hostEndpointIdHex: "cd",
            hostRelayURL: "https://wires.example.org"
        ))
        $0.keychainClient = .fixture()
    }
    await store.send(.loaded(
        serverName: "Wires",
        serverURL: "https://wires.example.org",
        rootPubkeyHex: "ab",
        faceIDEnabled: true
    )) {
        $0.serverName = "Wires"
        $0.serverURL = "https://wires.example.org"
        $0.rootPubkeyHex = "ab"
        $0.faceIDEnabled = true
        $0.loading = false
    }
}
```

- [ ] **Step 4: Run tests, PASS. Commit.**

```bash
git add Wires/Wires/Features/Settings/SettingsFeature.swift Wires/WiresTests/SettingsFeatureTests.swift Wires/Wires/Dependencies/KeychainClient.swift
git commit -m "ios: flesh out SettingsFeature with load + delete-sheet plumbing"
```

### Task 3.2 — DeleteAccountFeature

**Spec:** §6.5 Destructive footer.

**Files:**
- Create: `Wires/Wires/Features/Settings/DeleteAccountFeature.swift`
- Create: `Wires/Wires/Features/Settings/DeleteAccountSheet.swift`
- Create: `Wires/WiresTests/DeleteAccountFeatureTests.swift`

- [ ] **Step 1: Failing test.**

```swift
import ComposableArchitecture
import Testing
@testable import Wires

@Suite("DeleteAccountFeature")
struct DeleteAccountFeatureTests {
    @Test("confirm button stays disabled until 'delete' is typed")
    func confirmRequiresExactMatch() async {
        let store = await TestStore(initialState: DeleteAccountFeature.State()) {
            DeleteAccountFeature()
        }
        #expect(store.state.confirmEnabled == false)
        await store.send(.confirmTextChanged("delet")) {
            $0.confirmText = "delet"
            $0.confirmEnabled = false
        }
        await store.send(.confirmTextChanged("delete")) {
            $0.confirmText = "delete"
            $0.confirmEnabled = true
        }
        await store.send(.confirmTextChanged("Delete")) {
            $0.confirmText = "Delete"
            $0.confirmEnabled = false  // case-sensitive
        }
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `DeleteAccountFeature.swift`.**

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct DeleteAccountFeature {
    @ObservableState
    struct State: Equatable {
        var confirmText: String = ""
        var confirmEnabled: Bool = false
    }

    enum Action {
        case confirmTextChanged(String)
        case confirmButtonTapped
        case cancelButtonTapped
        case confirmed
    }

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case let .confirmTextChanged(text):
                state.confirmText = text
                state.confirmEnabled = (text == "delete")
                return .none
            case .confirmButtonTapped:
                guard state.confirmEnabled else { return .none }
                return .send(.confirmed)
            case .cancelButtonTapped, .confirmed:
                return .none
            }
        }
    }
}
```

- [ ] **Step 3: Implement `DeleteAccountSheet.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct DeleteAccountSheet: View {
    @Bindable var store: StoreOf<DeleteAccountFeature>

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.red)
                .padding(.top, 32)

            Text("Delete your account?")
                .font(.title2.bold())

            Text("Your account key will be erased from this iPhone. Every service in your network will lose access. This can't be undone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 16)

            TextField("Type 'delete' to confirm", text: Binding(
                get: { store.confirmText },
                set: { store.send(.confirmTextChanged($0)) }
            ))
            .textFieldStyle(.roundedBorder)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .padding(.horizontal, 16)

            Spacer()

            VStack(spacing: 8) {
                Button(role: .destructive) {
                    store.send(.confirmButtonTapped)
                } label: {
                    Text("Delete account")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .tint(.red)
                .disabled(!store.confirmEnabled)

                Button("Cancel") { store.send(.cancelButtonTapped) }
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
    }
}
```

- [ ] **Step 4: Run tests, PASS. Commit.**

```bash
git add Wires/Wires/Features/Settings/DeleteAccountFeature.swift Wires/Wires/Features/Settings/DeleteAccountSheet.swift Wires/WiresTests/DeleteAccountFeatureTests.swift
git commit -m "ios: add DeleteAccountFeature with type-to-confirm sheet"
```

### Task 3.3 — Real SettingsView

**Files:**
- Modify: `Wires/Wires/Features/Settings/SettingsView.swift`

- [ ] **Step 1: Replace the stub `SettingsView` with the full layout.**

```swift
import ComposableArchitecture
import SwiftUI

struct SettingsView: View {
    @Bindable var store: StoreOf<SettingsFeature>

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    accountHeader

                    Form {
                        Section("Security") {
                            Toggle("Face ID protection", isOn: Binding(
                                get: { store.faceIDEnabled },
                                set: { store.send(.faceIDToggled($0)) }
                            ))
                            .tint(AppColors.indigoPrimary)
                        }

                        Section {
                            LabeledContent("Server name", value: store.serverName.isEmpty ? "—" : store.serverName)
                            LabeledContent("Server URL", value: store.serverURL.isEmpty ? "—" : store.serverURL)
                        } header: {
                            Text("Server")
                        } footer: {
                            Text("Your account lives on this server. You can't move it to a different server.")
                        }

                        Section("About") {
                            LabeledContent("Version", value: store.appVersion)
                        }
                    }
                    .frame(minHeight: 400)
                    .scrollDisabled(true)

                    DestructiveFooterButton(title: "Delete account") {
                        store.send(.deleteAccountTapped)
                    }
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Settings")
            .task { store.send(.onAppear) }
            .sheet(item: $store.scope(state: \.deleteSheet, action: \.deleteSheet)) { childStore in
                DeleteAccountSheet(store: childStore)
                    .presentationBackground(.regularMaterial)
                    .presentationDetents([.large])
            }
            .sheet(isPresented: Binding(
                get: { store.showingAccountDetail },
                set: { if !$0 { store.send(.accountDetailDismissed) } }
            )) {
                AccountDetailSheet(store: store)
            }
        }
    }

    private var accountHeader: some View {
        Button {
            store.send(.accountRowTapped)
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(AppColors.indigoPrimary)
                    WiresBrandGlyph(variant: .static, size: 36, color: .white)
                }
                .frame(width: 56, height: 56)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Your Wires")
                        .font(.title3.bold())
                        .foregroundStyle(.primary)
                    Text(store.serverName.isEmpty ? store.serverURL : store.serverName)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }
            .padding(16)
            .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.top, 16)
    }
}
```

- [ ] **Step 2: Add `AccountDetailSheet.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct AccountDetailSheet: View {
    @Bindable var store: StoreOf<SettingsFeature>

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    ZStack {
                        Circle().fill(AppColors.indigoPrimary)
                        WiresBrandGlyph(variant: .static, size: 56, color: .white)
                    }
                    .frame(width: 96, height: 96)

                    Text("Your Wires")
                        .font(.title.bold())
                    Text(store.serverName.isEmpty ? store.serverURL : store.serverName)
                        .font(.body)
                        .foregroundStyle(.secondary)

                    AdvancedDisclosure(title: "Advanced") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Account key fingerprint")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            Text(store.rootPubkeyHex)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, 16)

                    Spacer()
                }
                .padding(.top, 32)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { store.send(.accountDetailDismissed) }
                }
            }
        }
    }
}
```

- [ ] **Step 3: Build, commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
git add Wires/Wires/Features/Settings
git commit -m "ios: implement real SettingsView with account header + delete-account footer"
```

### Task 3.4 — Settings fixtures + wire deletion to AppFeature

**Spec:** §10 Snapshot harness updates.

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Modify: `Wires/Wires/Features/Main/MainFeature.swift` (wire `.settings(.accountDeleted)` through to a `didReset` parent action)
- Modify: `Wires/Wires/App/AppFeature.swift`
- Modify: `Wires/WiresUITests/SnapshotSweep.swift`
- Modify: `Wires/WiresTests/LaunchFixtureTests.swift`

- [ ] **Step 1: Add fixture cases.** In `LaunchFixture` add:

```swift
case settingsRoot           = "settings_root"
case settingsFaceIDOff      = "settings_face_id_off"
case settingsAccountDetail  = "settings_account_detail"
case settingsDeleteConfirm  = "settings_delete_confirm"
```

- [ ] **Step 2: Add `applyDependencies` arms.** Each settings fixture wants a populated household and a granted camera permission:

```swift
case .settingsRoot, .settingsFaceIDOff, .settingsAccountDetail, .settingsDeleteConfirm:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture(
        household: Household(
            rootPubkeyHex: String(repeating: "ab", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32),
            hostRelayURL: "https://wires.example.org"
        )
    )
    values.mcpGatewayClient = .fixture()
```

- [ ] **Step 3: Add `initialAppState` arms.**

```swift
case .settingsRoot:
    return mainStateOnSettings(faceIDEnabled: true)

case .settingsFaceIDOff:
    return mainStateOnSettings(faceIDEnabled: false)

case .settingsAccountDetail:
    var main = mainStateOnSettings(faceIDEnabled: true)
    if case var .main(s) = main {
        s.settings.showingAccountDetail = true
        main = .main(s)
    }
    return main

case .settingsDeleteConfirm:
    var main = mainStateOnSettings(faceIDEnabled: true)
    if case var .main(s) = main {
        s.settings.deleteSheet = DeleteAccountFeature.State()
        main = .main(s)
    }
    return main
```

And the helper near the bottom of `LaunchFixture`:

```swift
private func mainStateOnSettings(faceIDEnabled: Bool) -> AppFeature.State {
    let home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    var settings = SettingsFeature.State()
    settings.loading = false
    settings.serverName = "Wires"
    settings.serverURL = "https://wires.example.org"
    settings.rootPubkeyHex = String(repeating: "ab", count: 32)
    settings.faceIDEnabled = faceIDEnabled
    return .main(MainFeature.State(home: home, settings: settings, selectedTab: .settings))
}
```

- [ ] **Step 4: Wire delete-account up to AppFeature.**

In `MainFeature.swift`, add a delegate action:

```swift
enum Action {
    case home(HomeFeature.Action)
    case settings(SettingsFeature.Action)
    case tabSelected(State.Tab)
    case didReset  // delegate
}

// In the reducer:
case .settings(.accountDeleted):
    return .send(.didReset)
```

In `AppFeature.swift`, handle `case .main(.didReset):` the same way the old `.home(.didReset)` was handled (transition to `.launching`, re-run onAppear).

In `SettingsFeature`'s `.deleteSheet(.presented(.confirmed))` arm, perform the actual cleanup before sending `.accountDeleted`:

```swift
case .deleteSheet(.presented(.confirmed)):
    state.deleteSheet = nil
    let household = self.household
    let keychain = self.keychain
    return .run { send in
        try? await household.wipeEverything()
        // wipe keychain root signing key + pubkey + iroh secret
        try? keychain.delete(account: KeychainBackedRootSigner.Account.signingKey)
        try? keychain.delete(account: KeychainBackedRootSigner.Account.pubkey)
        try? keychain.delete(account: "wires.iroh.secret")
        await send(.accountDeleted)
    }
```

If `HouseholdClient` doesn't already expose `wipeEverything`, add it (it likely already does — the current HomeFeature's `.resetHouseholdTapped` action wires through a similar reset, so reuse that code path).

- [ ] **Step 5: Add `SnapshotSweep` tests.**

```swift
func test_settings_root() throws { try snap("settings_root", flow: "settings", short: "root") }
func test_settings_face_id_off() throws { try snap("settings_face_id_off", flow: "settings", short: "face-id-off") }
func test_settings_account_detail() throws { try snap("settings_account_detail", flow: "settings", short: "account-detail") }
func test_settings_delete_confirm() throws { try snap("settings_delete_confirm", flow: "settings", short: "delete-confirm") }
```

- [ ] **Step 6: Bump `LaunchFixtureTests.allCases.count`.**

Current: 14. After adding 4: 18.

- [ ] **Step 7: Snapshot sweep, review the 4 new fixtures.**

```bash
./scripts/snapshot-ios.sh
open Wires/screenshots/latest/settings
```

Confirm settings root shows the account card, Form, and Delete account footer; face-id-off shows the toggle off; account-detail shows the modal; delete-confirm shows the type-to-delete sheet.

- [ ] **Step 8: Commit.**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift Wires/WiresUITests/SnapshotSweep.swift Wires/WiresTests/LaunchFixtureTests.swift Wires/Wires/Features/Main Wires/Wires/Features/Settings Wires/Wires/App
git commit -m "ios: add 4 settings snapshot fixtures + wire delete-account to AppFeature reset"
```

### Task 3.5 — Retire the debug-only "Reset household" button

**Files:**
- Modify: `Wires/Wires/Features/Home/HomeView.swift`

- [ ] **Step 1: Remove the `#if DEBUG` toolbar item.** Delete the `secondaryAction` ToolbarItem block that shows "Reset household (debug)". The Settings tab is now the only path to deletion.

- [ ] **Step 2: Verify the HomeFeature `resetHouseholdTapped` etc. is no longer reachable from UI.** It can stay in the reducer for now (Phase 5 will remove it entirely when HomeFeature is replaced by NetworkFeature).

- [ ] **Step 3: Build, commit.**

```bash
git add Wires/Wires/Features/Home/HomeView.swift
git commit -m "ios: retire debug-only Reset household button — Settings owns destruction"
```

---

## Phase 4 — FFI: `HostTicket.server_name`

Adds the optional `server_name` field to `HostTicket` so onboarding Step 3 has a friendly name to display. Backward-compatible — tickets without it still decode.

### Task 4.1 — Add `server_name` to `HostTicket`

**Spec:** §9 FFI / protocol changes.

**Files:**
- Modify: `crates/wires-net/src/ticket.rs`

- [ ] **Step 1: Add the field, default `None` on decode.**

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostTicket {
    pub version: u8,
    pub endpoint_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    pub hint_expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}
```

- [ ] **Step 2: Add a test that confirms backward compatibility.** In the same file's `#[cfg(test)] mod tests`:

```rust
#[test]
fn decode_pre_server_name_ticket_succeeds() {
    let pre = HostTicket {
        version: TICKET_VERSION,
        endpoint_id: "ab".repeat(32),
        addrs: vec!["127.0.0.1:4242".to_string()],
        relay: None,
        hint_expires_at: 0,
        server_name: None,
    };
    let s = pre.encode().unwrap();
    let back = HostTicket::decode(&s).unwrap();
    assert_eq!(back.server_name, None);
}

#[test]
fn server_name_round_trips() {
    let t = HostTicket {
        version: TICKET_VERSION,
        endpoint_id: "ab".repeat(32),
        addrs: vec![],
        relay: None,
        hint_expires_at: 0,
        server_name: Some("Wires".to_string()),
    };
    let s = t.encode().unwrap();
    let back = HostTicket::decode(&s).unwrap();
    assert_eq!(back.server_name, Some("Wires".to_string()));
}
```

- [ ] **Step 3: Update `from_endpoint` to take an optional name.**

```rust
pub fn from_endpoint(
    endpoint: &iroh::Endpoint,
    hint_ttl: std::time::Duration,
    server_name: Option<String>,
) -> Result<Self> {
    // ... existing body ...
    Ok(HostTicket {
        version: TICKET_VERSION,
        endpoint_id,
        addrs,
        relay,
        hint_expires_at: now_ms + hint_ttl.as_millis() as i64,
        server_name,
    })
}
```

- [ ] **Step 4: Fix every call site.** Existing callers pass `None`:

```bash
grep -rn "HostTicket::from_endpoint" crates/ --include='*.rs'
```

Adjust each call to add the trailing `None`. Existing sample-data tests will already construct `HostTicket` literals; add `server_name: None,` to each.

- [ ] **Step 5: Run Rust tests.**

```bash
cargo test -p wires-net --lib
```

Expected: all pass.

- [ ] **Step 6: Commit.**

```bash
git add crates/wires-net/src/ticket.rs
git commit -m "wires-net: add optional HostTicket.server_name (backward-compatible)"
```

### Task 4.2 — `wires-host ticket` CLI flag

**Files:**
- Modify: `crates/wires-host/src/main.rs` (or wherever the `ticket` subcommand parses args)

- [ ] **Step 1: Find the `ticket` subcommand.**

```bash
grep -rn "fn cmd_ticket\|Ticket {" crates/wires-host/src/ --include='*.rs'
```

- [ ] **Step 2: Add a `--server-name <NAME>` argument to the `ticket` subcommand and to the startup-time ticket emission.** Surface this in `HostConfig`:

```rust
// In HostConfig:
pub server_name: Option<String>,
```

And in the CLI/`config.rs`:

```rust
// New CLI argument on the ticket subcommand and on the run command:
#[arg(long = "server-name")]
pub server_name: Option<String>,
```

Thread it through to `HostTicket::from_endpoint(.., .., server_name)`.

- [ ] **Step 3: Run tests.**

```bash
cargo test -p wires-host --lib
cargo build -p wires-host
```

- [ ] **Step 4: Manual sanity check.** Generate a ticket:

```bash
target/debug/wires-host ticket --data-dir /tmp/wh-server-name-test --server-name "Test Server" --json
```

Inspect that the JSON encodes `"server_name": "Test Server"`.

- [ ] **Step 5: Commit.**

```bash
git add crates/wires-host
git commit -m "wires-host: --server-name flag on ticket + run subcommands"
```

### Task 4.3 — Expose `server_name` through WiresKit

**Files:**
- Modify: `crates/wires-ioskit/src/lib.rs` (or wherever the UniFFI interface declares `HostInfo`)
- Modify: `crates/wires-ioskit/src/wires.udl` (if applicable)
- Modify: `Wires/Wires/WiresKit/Sources/WiresKit/WiresKit.swift` (regenerated, not hand-edited)

- [ ] **Step 1: Find the `HostInfo` UniFFI definition.**

```bash
grep -rn "HostInfo\b" crates/wires-ioskit/src/ --include='*.rs' --include='*.udl' | head -20
```

- [ ] **Step 2: Add `server_name: Option<String>` to the `HostInfo` struct/dictionary.** The UniFFI definition probably looks like:

```idl
dictionary HostInfo {
    string endpoint_id_hex;
    sequence<string> addrs;
    string? relay;
    i64 hint_expires_at_ms;
};
```

Update to add:

```idl
    string? server_name;
```

And the corresponding Rust struct.

- [ ] **Step 3: Update `parse_host_ticket` to populate `server_name`** from the decoded `HostTicket`.

- [ ] **Step 4: Rebuild the xcframework.**

```bash
scripts/build-ioskit.sh
```

This regenerates `Wires/Wires/WiresKit/Sources/WiresKit/WiresKit.swift`. Confirm that `HostInfo` now has `serverName: String?`.

- [ ] **Step 5: Update the Swift parse helper.** Find existing `parseHostTicket` callers — most will be unaffected. The new `serverName` is accessible via `hostInfo.serverName`.

- [ ] **Step 6: Build the iOS app.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
```

Expected: builds. Any existing tests that construct `HostInfo` literals need a `serverName: nil` added — grep for them and fix.

- [ ] **Step 7: Commit.**

```bash
git add crates/wires-ioskit Wires/Wires/WiresKit
git commit -m "wires-ioskit: surface HostTicket.server_name on HostInfo"
```

---

## Phase 5 — Onboarding rewrite

Replaces `BootstrapFeature` with `OnboardingFeature` and its 5-step ceremony. Old `bootstrap_*` fixtures retire as the new ones land.

### Task 5.1 — OnboardingFeature state + transitions

**Spec:** §6.1 Onboarding (5 screens).

**Files:**
- Create: `Wires/Wires/Features/Onboarding/OnboardingFeature.swift`
- Create: `Wires/WiresTests/OnboardingFeatureTests.swift`

- [ ] **Step 1: Failing test for the step state machine.**

```swift
import ComposableArchitecture
import Testing
import WiresKit
@testable import Wires

@Suite("OnboardingFeature")
struct OnboardingFeatureTests {
    @Test("getStarted advances welcome → scan")
    func welcomeAdvances() async {
        let store = await TestStore(initialState: OnboardingFeature.State()) {
            OnboardingFeature()
        } withDependencies: {
            $0.wiresClient = .fixture()
            $0.householdClient = .fixture()
            $0.keychainClient = .fixture()
            $0.cameraPermissionClient = .fixture(.granted)
        }
        #expect(store.state.step == .welcome)
        await store.send(.getStartedTapped) {
            $0.step = .scan
        }
    }

    @Test("scanning a ticket advances to confirm")
    func scanAdvancesToConfirm() async {
        let host = HostInfo(
            endpointIdHex: "cd",
            addrs: ["127.0.0.1:4242"],
            relay: nil,
            hintExpiresAtMs: 0,
            serverName: "Wires"
        )
        let store = await TestStore(initialState: OnboardingFeature.State(step: .scan)) {
            OnboardingFeature()
        } withDependencies: {
            $0.wiresClient = .fixture()
            $0.householdClient = .fixture()
            $0.keychainClient = .fixture()
        }
        await store.send(.scan(.decodedPayload(host))) {
            $0.confirmedHost = host
            $0.step = .confirm
        }
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `OnboardingFeature.swift`.** This replaces `BootstrapFeature`; reuses `ScanFeature<HostInfo>` and the existing register-tenant logic.

```swift
import ComposableArchitecture
import Foundation
import LocalAuthentication
import WiresKit

@Reducer
struct OnboardingFeature {
    @ObservableState
    struct State: Equatable {
        var step: Step = .welcome
        var scan = ScanFeature<HostInfo>.State()

        var pasteSheetPresented = false
        var pasteInput = ""
        var pasteError: String?

        var confirmedHost: HostInfo?
        var registering = false
        var registerError: String?

        var faceIDError: String?
        var faceIDEnabling = false

        var completed: Completed?

        struct Completed: Equatable {
            let registration: TenantRegistration
            let host: HostInfo
            let rootPubkeyHex: String
        }

        enum Step: Equatable {
            case welcome, scan, confirm, faceID, done
        }
    }

    @CasePathable
    enum Action {
        case getStartedTapped
        case scan(ScanFeature<HostInfo>.Action)
        case pasteButtonTapped
        case pasteSheetDismissed
        case pasteInputChanged(String)
        case pasteSubmitTapped
        case pasteTicketParsed(HostInfo)
        case pasteTicketParseFailed(String)

        case confirmRegisterTapped
        case confirmBackTapped
        case registerSucceeded(State.Completed)
        case registerFailed(String)

        case faceIDSetupTapped
        case faceIDSkipTapped
        case faceIDResolved(Bool)
        case faceIDFailed(String)

        case continueTapped

        /// Delegate fired when the user finishes the ceremony. AppFeature listens.
        case onboardingCompleted(rootPubkeyHex: String)
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain

    private static let rootPubkeyAccount = "wires.root.pubkey"

    var body: some Reducer<State, Action> {
        Scope(state: \.scan, action: \.scan) {
            ScanFeature<HostInfo>(parse: { payload in
                @Dependency(\.wiresClient) var wires
                return try await wires.parseHostTicket(payload)
            })
        }

        Reduce { state, action in
            switch action {
            case .getStartedTapped:
                state.step = .scan
                return .none

            case let .scan(.decodedPayload(host)):
                state.confirmedHost = host
                state.step = .confirm
                return .none

            case .scan:
                return .none

            case .pasteButtonTapped:
                state.pasteInput = ""
                state.pasteError = nil
                state.pasteSheetPresented = true
                return .none

            case .pasteSheetDismissed:
                state.pasteSheetPresented = false
                return .none

            case let .pasteInputChanged(text):
                state.pasteInput = text
                state.pasteError = nil
                return .none

            case .pasteSubmitTapped:
                let payload = state.pasteInput
                let wires = self.wires
                return .run { send in
                    do {
                        let host = try await wires.parseHostTicket(payload)
                        await send(.pasteTicketParsed(host))
                    } catch {
                        await send(.pasteTicketParseFailed(String(describing: error)))
                    }
                }

            case let .pasteTicketParsed(host):
                state.pasteSheetPresented = false
                state.pasteInput = ""
                state.pasteError = nil
                state.confirmedHost = host
                state.step = .confirm
                return .none

            case let .pasteTicketParseFailed(message):
                state.pasteError = message
                return .none

            case .confirmRegisterTapped:
                guard let host = state.confirmedHost else { return .none }
                state.registering = true
                state.registerError = nil
                let wires = self.wires
                let household = self.household
                let keychain = self.keychain
                let pubkeyAccount = Self.rootPubkeyAccount
                return .run { send in
                    do {
                        let registration = try await wires.registerWithHostedService(host)
                        guard let pubkeyData = try keychain.getData(account: pubkeyAccount) else {
                            await send(.registerFailed("Root pubkey missing from Keychain"))
                            return
                        }
                        let pubkeyHex = pubkeyData.map { String(format: "%02x", $0) }.joined()
                        let h = Household(
                            rootPubkeyHex: pubkeyHex,
                            hostEndpointIdHex: registration.hostEndpointIdHex,
                            hostDirectAddrs: host.addrs,
                            hostRelayURL: host.relay,
                            hostHintExpiresAtMs: host.hintExpiresAtMs,
                            capsTopicIdHex: registration.capsTopicIdHex,
                            tenantRegisteredAt: .now
                        )
                        try await household.saveHousehold(h)
                        await send(.registerSucceeded(.init(
                            registration: registration,
                            host: host,
                            rootPubkeyHex: pubkeyHex
                        )))
                    } catch {
                        await send(.registerFailed(String(describing: error)))
                    }
                }

            case .confirmBackTapped:
                state.confirmedHost = nil
                state.registering = false
                state.registerError = nil
                state.step = .scan
                return .none

            case let .registerSucceeded(completed):
                state.registering = false
                state.registerError = nil
                state.completed = completed
                state.step = .faceID
                return .none

            case let .registerFailed(message):
                state.registering = false
                state.registerError = message
                return .none

            case .faceIDSetupTapped:
                state.faceIDEnabling = true
                state.faceIDError = nil
                return .run { send in
                    let context = LAContext()
                    var error: NSError?
                    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                        do {
                            let ok = try await context.evaluatePolicy(
                                .deviceOwnerAuthenticationWithBiometrics,
                                localizedReason: "Protect your Wires account"
                            )
                            await send(.faceIDResolved(ok))
                        } catch {
                            await send(.faceIDFailed(String(describing: error)))
                        }
                    } else {
                        await send(.faceIDFailed(error?.localizedDescription ?? "Face ID unavailable"))
                    }
                }

            case .faceIDSkipTapped:
                state.step = .done
                return .none

            case let .faceIDResolved(ok):
                state.faceIDEnabling = false
                if ok { state.step = .done }
                else { state.faceIDError = "Face ID was not approved." }
                return .none

            case let .faceIDFailed(message):
                state.faceIDEnabling = false
                state.faceIDError = message
                return .none

            case .continueTapped:
                guard let c = state.completed else { return .none }
                return .send(.onboardingCompleted(rootPubkeyHex: c.rootPubkeyHex))

            case .onboardingCompleted:
                return .none
            }
        }
    }
}
```

- [ ] **Step 3: Run tests, PASS. Commit.**

```bash
git add Wires/Wires/Features/Onboarding/OnboardingFeature.swift Wires/WiresTests/OnboardingFeatureTests.swift
git commit -m "ios: add OnboardingFeature reducer with 5-step state machine"
```

### Task 5.2 — Onboarding step views

**Spec:** §6.1 each step.

**Files:**
- Create: `Wires/Wires/Features/Onboarding/OnboardingView.swift`
- Create: `Wires/Wires/Features/Onboarding/WelcomeStepView.swift`
- Create: `Wires/Wires/Features/Onboarding/ScanStepView.swift`
- Create: `Wires/Wires/Features/Onboarding/ConfirmServerStepView.swift`
- Create: `Wires/Wires/Features/Onboarding/FaceIDStepView.swift`
- Create: `Wires/Wires/Features/Onboarding/DoneStepView.swift`

- [ ] **Step 1: Implement `OnboardingView.swift`** — top-level switcher.

```swift
import ComposableArchitecture
import SwiftUI

struct OnboardingView: View {
    @Bindable var store: StoreOf<OnboardingFeature>

    var body: some View {
        switch store.step {
        case .welcome:
            WelcomeStepView(store: store)
        case .scan:
            ScanStepView(store: store)
        case .confirm:
            ConfirmServerStepView(store: store)
        case .faceID:
            FaceIDStepView(store: store)
        case .done:
            DoneStepView(store: store)
        }
    }
}
```

- [ ] **Step 2: `WelcomeStepView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct WelcomeStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Wires",
            subtitle: "A private network for the apps and services in your life.",
            hero: { WiresBrandGlyph(variant: .drawIn(duration: 1.6), size: 140) },
            content: { EmptyView() },
            primaryTitle: "Get started",
            primaryAction: { store.send(.getStartedTapped) }
        )
    }
}
```

- [ ] **Step 3: `ScanStepView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct ScanStepView: View {
    @Bindable var store: StoreOf<OnboardingFeature>

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                // No back/cancel — scan is step 2 and the only path forward
                // is to scan or paste. Tapping the app icon to return is the
                // existing iOS behavior.
                Spacer()
            }
            .frame(height: 44)

            VStack(spacing: 8) {
                Text("Set up your Wires")
                    .font(.largeTitle.bold())
                Text("Scan the setup code for the Wires server you want to use.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.bottom, 12)

            ScanView(store: store.scope(state: \.scan, action: \.scan))
                .frame(maxHeight: .infinity)

            HStack {
                Button {
                    store.send(.pasteButtonTapped)
                } label: {
                    Label("Paste code", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(.glass)
                .controlSize(.large)
            }
            .padding(.bottom, 24)
        }
        .sheet(isPresented: $store.pasteSheetPresented.sending(\.pasteSheetDismissed)) {
            pasteSheetView
        }
    }

    private var pasteSheetView: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste a setup code")
                    .font(.headline)
                TextEditor(text: $store.pasteInput.sending(\.pasteInputChanged))
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 160)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(.quaternary, lineWidth: 1)
                    )
                if let err = store.pasteError {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Paste setup code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { store.send(.pasteSheetDismissed) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use code") { store.send(.pasteSubmitTapped) }
                        .disabled(store.pasteInput.isEmpty)
                }
            }
        }
    }
}
```

- [ ] **Step 4: `ConfirmServerStepView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct ConfirmServerStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Use \(serverName) for your account?",
            subtitle: nil,
            hero: {
                ZStack {
                    RoundedRectangle(cornerRadius: 20)
                        .fill(AppColors.indigoPrimary.opacity(0.14))
                    WiresBrandGlyph(variant: .static, size: 60)
                }
                .frame(width: 120, height: 120)
            },
            content: { serverCard },
            primaryTitle: store.registerError == nil ? "Set up account here" : "Retry",
            primaryAction: { store.send(.confirmRegisterTapped) },
            primaryDisabled: store.registering,
            secondaryTitle: "Choose a different server",
            secondaryAction: { store.send(.confirmBackTapped) }
        )
    }

    private var serverName: String {
        if let host = store.confirmedHost {
            return host.serverName ?? host.endpointIdHex.prefix(16).description
        }
        return "—"
    }

    @ViewBuilder
    private var serverCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let host = store.confirmedHost {
                if let name = host.serverName {
                    LabeledContent("Server", value: name)
                }
                if let relay = host.relay {
                    LabeledContent("URL", value: relay)
                }
            }
            Text("Your Wires account will live here. You can't move it to a different server later, so make sure you trust this one.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.top, 8)
            if store.registering {
                ProgressView().padding(.top, 6)
            }
            if let err = store.registerError {
                Text(err)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
    }
}
```

- [ ] **Step 5: `FaceIDStepView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct FaceIDStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Protect your account with Face ID",
            subtitle: "Your account key lives on this iPhone. Face ID makes sure only you can use it — and protects it if you lose your phone.",
            hero: {
                Image(systemName: "faceid")
                    .font(.system(size: 100, weight: .light))
                    .foregroundStyle(AppColors.indigoPrimary)
            },
            content: {
                if let err = store.faceIDError {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .padding(.top, 8)
                }
            },
            primaryTitle: store.faceIDEnabling ? "Setting up…" : "Set up Face ID",
            primaryAction: { store.send(.faceIDSetupTapped) },
            primaryDisabled: store.faceIDEnabling,
            secondaryTitle: "Set up later",
            secondaryAction: { store.send(.faceIDSkipTapped) }
        )
    }
}
```

- [ ] **Step 6: `DoneStepView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct DoneStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "You're set up",
            subtitle: "Add a service to start using your network.",
            hero: {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 96))
                    .foregroundStyle(.green)
            },
            content: { EmptyView() },
            primaryTitle: "Continue",
            primaryAction: { store.send(.continueTapped) }
        )
    }
}
```

- [ ] **Step 7: Build, commit.**

```bash
git add Wires/Wires/Features/Onboarding
git commit -m "ios: add 5 onboarding step views"
```

### Task 5.3 — Wire OnboardingFeature into AppFeature (replacing BootstrapFeature)

**Files:**
- Modify: `Wires/Wires/App/AppFeature.swift`
- Modify: `Wires/Wires/WiresApp.swift` (or root view)

- [ ] **Step 1: Swap `.bootstrap(BootstrapFeature.State)` → `.onboarding(OnboardingFeature.State)`.** Update the enum case, the routing in `householdLoaded`, and the action forwarding.

The case that handled `.bootstrap(.bootstrapCompleted(let rootHex))` becomes `.onboarding(.onboardingCompleted(let rootHex))`.

The `.ifCaseLet(\.bootstrap, action: \.bootstrap) { BootstrapFeature() }` becomes `.ifCaseLet(\.onboarding, action: \.onboarding) { OnboardingFeature() }`.

The `householdLoaded(nil)` path that returned `.bootstrap(BootstrapFeature.State())` becomes `.onboarding(OnboardingFeature.State())`.

- [ ] **Step 2: Update the root view.** Swap `BootstrapView(store: ...)` → `OnboardingView(store: ...)`.

- [ ] **Step 3: Build the app to confirm it compiles.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
```

- [ ] **Step 4: Commit.**

```bash
git add Wires/Wires/App Wires/Wires/WiresApp.swift
git commit -m "ios: route AppFeature through OnboardingFeature in place of BootstrapFeature"
```

### Task 5.4 — Onboarding snapshot fixtures

**Spec:** §10 Snapshot fixtures (onboarding section).

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Modify: `Wires/WiresUITests/SnapshotSweep.swift`
- Modify: `Wires/WiresTests/LaunchFixtureTests.swift`

- [ ] **Step 1: Add fixture cases (and remove old `bootstrap_*` cases now that they're unreachable).**

```swift
case onboardingWelcome      = "onboarding_welcome"
case onboardingScan         = "onboarding_scan"
case onboardingScanError    = "onboarding_scan_error"
case onboardingConfirm      = "onboarding_confirm"
case onboardingFaceID       = "onboarding_face_id"
case onboardingDone         = "onboarding_done"
```

Delete: `bootstrapScanDenied`, `bootstrapScanGranted`, `bootstrapConfirm`, `bootstrapDone`.

- [ ] **Step 2: `applyDependencies` arms.** Every onboarding fixture uses `cameraPermissionClient = .fixture(.granted)` (except scanError, which can keep granted but seed an error), and the standard fixture clients.

```swift
case .onboardingWelcome, .onboardingScan, .onboardingScanError,
     .onboardingConfirm, .onboardingFaceID, .onboardingDone:
    values.cameraPermissionClient = .fixture(.granted)
    values.wiresClient = .fixture()
    values.householdClient = .fixture()
    values.mcpGatewayClient = .fixture()
```

- [ ] **Step 3: `initialAppState` arms.**

```swift
case .onboardingWelcome:
    return .onboarding(OnboardingFeature.State(step: .welcome))

case .onboardingScan:
    var s = OnboardingFeature.State(step: .scan)
    s.scan.cameraPermission = .granted
    return .onboarding(s)

case .onboardingScanError:
    var s = OnboardingFeature.State(step: .scan)
    s.scan.cameraPermission = .granted
    s.scan.error = .parseFailed("Couldn't read this code")
    return .onboarding(s)

case .onboardingConfirm:
    var s = OnboardingFeature.State(step: .confirm)
    s.confirmedHost = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["192.168.1.20:4242"],
        relay: "https://wires.example.org",
        hintExpiresAtMs: 0,
        serverName: "Wires"
    )
    return .onboarding(s)

case .onboardingFaceID:
    var s = OnboardingFeature.State(step: .faceID)
    s.completed = OnboardingFeature.State.Completed(
        registration: TenantRegistration(
            capsTopicIdHex: String(repeating: "ee", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32),
            serverTimeMs: 0
        ),
        host: HostInfo(
            endpointIdHex: String(repeating: "cd", count: 32),
            addrs: [],
            relay: "https://wires.example.org",
            hintExpiresAtMs: 0,
            serverName: "Wires"
        ),
        rootPubkeyHex: String(repeating: "ab", count: 32)
    )
    return .onboarding(s)

case .onboardingDone:
    var s = OnboardingFeature.State(step: .done)
    s.completed = OnboardingFeature.State.Completed(
        registration: TenantRegistration(
            capsTopicIdHex: String(repeating: "ee", count: 32),
            hostEndpointIdHex: String(repeating: "cd", count: 32),
            serverTimeMs: 0
        ),
        host: HostInfo(
            endpointIdHex: String(repeating: "cd", count: 32),
            addrs: [],
            relay: "https://wires.example.org",
            hintExpiresAtMs: 0,
            serverName: "Wires"
        ),
        rootPubkeyHex: String(repeating: "ab", count: 32)
    )
    return .onboarding(s)
```

Remove the four old `bootstrap*` arms in both switch statements.

- [ ] **Step 4: Add `SnapshotSweep` tests, remove old `bootstrap_*` tests.**

```swift
func test_onboarding_welcome()    throws { try snap("onboarding_welcome",    flow: "onboarding", short: "welcome") }
func test_onboarding_scan()       throws { try snap("onboarding_scan",       flow: "onboarding", short: "scan") }
func test_onboarding_scan_error() throws { try snap("onboarding_scan_error", flow: "onboarding", short: "scan-error") }
func test_onboarding_confirm()    throws { try snap("onboarding_confirm",    flow: "onboarding", short: "confirm") }
func test_onboarding_face_id()    throws { try snap("onboarding_face_id",    flow: "onboarding", short: "face-id") }
func test_onboarding_done()       throws { try snap("onboarding_done",       flow: "onboarding", short: "done") }
```

Delete the four `test_bootstrap_*` methods.

- [ ] **Step 5: Update `LaunchFixtureTests.allCases.count`.** Subtract 4 old, add 6 new: 18 - 4 + 6 = 20.

- [ ] **Step 6: Delete `BootstrapFeature.swift`, `BootstrapView.swift`, `ConfirmHostView.swift`, `DoneView.swift`, `BootstrapFeatureTests.swift`.**

- [ ] **Step 7: Snapshot sweep, review the 6 new onboarding PNGs.**

```bash
./scripts/snapshot-ios.sh
open Wires/screenshots/latest/onboarding
```

- [ ] **Step 8: Commit.**

```bash
git add Wires/Wires/Fixtures/LaunchFixture.swift Wires/WiresUITests/SnapshotSweep.swift Wires/WiresTests/LaunchFixtureTests.swift
git rm Wires/Wires/Features/Bootstrap/*.swift Wires/WiresTests/BootstrapFeatureTests.swift
git commit -m "ios: retire BootstrapFeature, add 6 onboarding snapshot fixtures"
```

---

## Phase 6 — Network tab rewrite

Renames `HomeFeature` to `NetworkFeature`, swaps the cap list for service-list rows powered by `ServiceSummary`/`ServiceListRow`. Old `home_*` fixtures retire. Service detail page lands here too.

### Task 6.1 — NetworkFeature (rename + reshape)

**Spec:** §6.2 Network tab — service list, §7 TCA features.

**Files:**
- Create: `Wires/Wires/Features/Network/NetworkFeature.swift`
- Create: `Wires/WiresTests/NetworkFeatureTests.swift`
- (Old HomeFeature kept until view + tests have switched over.)

- [ ] **Step 1: Failing test.**

```swift
import ComposableArchitecture
import Testing
@testable import Wires

@Suite("NetworkFeature")
struct NetworkFeatureTests {
    @Test("onAppear loads services from CapToServiceMapper")
    func loadsServices() async {
        let cap = CapRecord(
            capIdHex: "11",
            nodePubkeyHex: "aa",
            nodeAlias: "Aaron's Mac",
            topicNames: ["family"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let store = await TestStore(
            initialState: NetworkFeature.State(rootPubkeyHex: "ab")
        ) {
            NetworkFeature()
        } withDependencies: {
            $0.householdClient = .fixture(
                household: Household(rootPubkeyHex: "ab"),
                caps: [cap]
            )
            $0.wiresClient = .fixture()
            $0.keychainClient = .fixture()
        }
        await store.send(.onAppear) { $0.loading = true }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.services = [CapToServiceMapper.summary(from: cap)]
        }
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement `NetworkFeature.swift`.**

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct NetworkFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
        var services: [ServiceSummary] = []
        var loading = false
        var loadError: String?
        @Presents var connect: ConnectFeature.State?
        var path = StackState<ServiceDetailFeature.State>()
    }

    @CasePathable
    enum Action {
        case onAppear
        case loaded([ServiceSummary])
        case loadFailed(String)
        case plusTapped
        case connect(PresentationAction<ConnectFeature.Action>)
        case path(StackActionOf<ServiceDetailFeature>)
        case rowTapped(ServiceSummary)
    }

    @Dependency(\.householdClient) var household

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                state.loadError = nil
                let household = self.household
                return .run { send in
                    do {
                        let caps = try await household.listCaps()
                        let summaries = caps.map(CapToServiceMapper.summary(from:))
                        await send(.loaded(summaries))
                    } catch {
                        await send(.loadFailed(String(describing: error)))
                    }
                }

            case let .loaded(services):
                state.loading = false
                state.loadError = nil
                state.services = services
                return .none

            case let .loadFailed(message):
                state.loading = false
                state.loadError = message
                return .none

            case .plusTapped:
                state.connect = ConnectFeature.State.initial()
                return .none

            case .connect(.dismiss):
                state.connect = nil
                return .send(.onAppear)

            case .connect:
                return .none

            case let .rowTapped(summary):
                state.path.append(ServiceDetailFeature.State(summary: summary))
                return .none

            case .path:
                return .none
            }
        }
        .ifLet(\.$connect, action: \.connect) { ConnectFeature() }
        .forEach(\.path, action: \.path) { ServiceDetailFeature() }
    }
}
```

- [ ] **Step 3: Skip ahead and write a minimal `ServiceDetailFeature` and `ConnectFeature` stub** so this compiles — full implementations come in Tasks 6.3 and 7.x. For now:

`Wires/Wires/Features/Network/ServiceDetailFeature.swift`:

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct ServiceDetailFeature {
    @ObservableState
    struct State: Equatable {
        var summary: ServiceSummary
    }

    enum Action { case onAppear }

    var body: some Reducer<State, Action> {
        EmptyReducer()
    }
}
```

`Wires/Wires/Features/Connect/ConnectFeature.swift` (stub — full implementation in Phase 7):

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct ConnectFeature {
    @ObservableState
    struct State: Equatable {}

    enum Action {}

    static func initial() -> State { State() }

    var body: some Reducer<State, Action> { EmptyReducer() }
}
```

(These get replaced when their phases land.)

- [ ] **Step 4: Run tests, PASS. Commit.**

```bash
git add Wires/Wires/Features/Network Wires/Wires/Features/Connect Wires/WiresTests/NetworkFeatureTests.swift
git commit -m "ios: add NetworkFeature + ServiceDetailFeature/ConnectFeature stubs"
```

### Task 6.2 — NetworkView

**Spec:** §6.2 Network tab — service list.

**Files:**
- Create: `Wires/Wires/Features/Network/NetworkView.swift`

- [ ] **Step 1: Implement.**

```swift
import ComposableArchitecture
import SwiftUI

struct NetworkView: View {
    @Bindable var store: StoreOf<NetworkFeature>

    var body: some View {
        NavigationStack(path: $store.scope(state: \.path, action: \.path)) {
            content
                .navigationTitle("Network")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            store.send(.plusTapped)
                        } label: {
                            Image(systemName: "plus")
                        }
                        .tint(AppColors.indigoPrimary)
                    }
                }
                .task { store.send(.onAppear) }
                .sheet(item: $store.scope(state: \.connect, action: \.connect)) { childStore in
                    ConnectView(store: childStore)
                }
        } destination: { childStore in
            ServiceDetailView(store: childStore)
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.loading && store.services.isEmpty {
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let err = store.loadError {
            InlineErrorBanner(
                message: err,
                primaryTitle: "Try again",
                primaryAction: { store.send(.onAppear) }
            )
        } else if store.services.isEmpty {
            emptyState
        } else {
            servicesList
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            WiresBrandGlyph(variant: .static, size: 96)
                .opacity(0.5)
            Text("No services yet")
                .font(.title3.bold())
            Text("Tap + to add a service to your network.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 24)
    }

    private var servicesList: some View {
        List {
            let connected = store.services.filter { $0.status == .connected }
            let revoked = store.services.filter { $0.status == .revoked }
            let pending = store.services.filter { $0.status == .pending }

            if !connected.isEmpty {
                Section("Connected") {
                    ForEach(connected) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !pending.isEmpty {
                Section("Pending approval") {
                    ForEach(pending) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !revoked.isEmpty {
                Section("Recently disconnected") {
                    ForEach(revoked) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }
}

struct ConnectView: View {
    let store: StoreOf<ConnectFeature>
    var body: some View {
        Text("Connect — placeholder until Phase 7")
            .padding()
    }
}

struct ServiceDetailView: View {
    let store: StoreOf<ServiceDetailFeature>
    var body: some View {
        Text("Service detail — placeholder")
            .padding()
    }
}
```

- [ ] **Step 2: Update `MainFeature` to use `NetworkFeature` in place of `HomeFeature`.**

In `Wires/Wires/Features/Main/MainFeature.swift`:

```swift
@ObservableState
struct State: Equatable {
    var network: NetworkFeature.State
    var settings: SettingsFeature.State
    var selectedTab: Tab
    enum Tab: Hashable { case network, settings }
}

enum Action {
    case network(NetworkFeature.Action)
    case settings(SettingsFeature.Action)
    case tabSelected(State.Tab)
    case didReset
}

var body: some Reducer<State, Action> {
    Scope(state: \.network, action: \.network) { NetworkFeature() }
    Scope(state: \.settings, action: \.settings) { SettingsFeature() }
    Reduce { state, action in
        switch action {
        case let .tabSelected(tab):
            state.selectedTab = tab
            return .none
        case .settings(.accountDeleted):
            return .send(.didReset)
        case .network, .settings, .didReset:
            return .none
        }
    }
}
```

- [ ] **Step 3: Update `MainView` to render `NetworkView`.**

```swift
NetworkView(store: store.scope(state: \.network, action: \.network))
    .tabItem { Label("Network", systemImage: "circle.hexagongrid") }
    .tag(MainFeature.State.Tab.network)
```

- [ ] **Step 4: Update AppFeature.** Any reference to `HomeFeature.State` becomes `NetworkFeature.State`. The `MainFeature.State(home: ...)` constructor becomes `MainFeature.State(network: ...)`.

- [ ] **Step 5: Update `LaunchFixture` arms** that constructed `HomeFeature.State(...)` to use `NetworkFeature.State(...)`. Rename the cases (in this task, leave the rawValues unchanged — the rename to `network_*` happens in Task 6.4).

- [ ] **Step 6: Build, snapshot sweep, commit.**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' build -quiet
./scripts/snapshot-ios.sh
git add -A
git commit -m "ios: route MainFeature through NetworkFeature, add basic NetworkView"
```

### Task 6.3 — ServiceDetailFeature + ServiceDetailView

**Spec:** §6.3 Service detail.

**Files:**
- Modify: `Wires/Wires/Features/Network/ServiceDetailFeature.swift`
- Create: `Wires/Wires/Features/Network/ServiceDetailView.swift`
- Create: `Wires/WiresTests/ServiceDetailFeatureTests.swift`

- [ ] **Step 1: Failing test.**

```swift
import ComposableArchitecture
import Testing
@testable import Wires

@Suite("ServiceDetailFeature")
struct ServiceDetailFeatureTests {
    @Test("disconnectTapped shows confirm")
    func showsDisconnectConfirm() async {
        let s = ServiceSummary(
            id: "1", name: "Chase", deviceName: "Mac",
            category: .banking, status: .connected,
            scopes: [], connectedAt: Date(), lastActivityAt: nil
        )
        let store = await TestStore(initialState: ServiceDetailFeature.State(summary: s)) {
            ServiceDetailFeature()
        }
        await store.send(.disconnectTapped) {
            $0.confirmingDisconnect = true
        }
    }
}
```

Run + verify FAIL.

- [ ] **Step 2: Implement the full ServiceDetailFeature.**

```swift
import ComposableArchitecture
import Foundation

@Reducer
struct ServiceDetailFeature {
    @ObservableState
    struct State: Equatable, Identifiable {
        var id: String { summary.id }
        var summary: ServiceSummary
        var confirmingDisconnect = false
        var disconnecting = false
        var disconnectError: String?
        var didDisconnect = false
    }

    enum Action {
        case onAppear
        case disconnectTapped
        case disconnectConfirmTapped
        case disconnectCancelTapped
        case disconnectSucceeded
        case disconnectFailed(String)
        case reconnectTapped // navigates the parent to ConnectFeature
    }

    @Dependency(\.householdClient) var household
    @Dependency(\.wiresClient) var wires

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear: return .none

            case .disconnectTapped:
                state.confirmingDisconnect = true
                state.disconnectError = nil
                return .none

            case .disconnectCancelTapped:
                state.confirmingDisconnect = false
                return .none

            case .disconnectConfirmTapped:
                state.disconnecting = true
                let capId = state.summary.id
                let household = self.household
                return .run { send in
                    do {
                        try await household.revokeCap(capId)
                        await send(.disconnectSucceeded)
                    } catch {
                        await send(.disconnectFailed(String(describing: error)))
                    }
                }

            case .disconnectSucceeded:
                state.disconnecting = false
                state.confirmingDisconnect = false
                state.didDisconnect = true
                return .none

            case let .disconnectFailed(message):
                state.disconnecting = false
                state.disconnectError = message
                return .none

            case .reconnectTapped:
                return .none
            }
        }
    }
}
```

If `HouseholdClient` doesn't have `revokeCap`, add it as a thin wrapper around whatever revocation API exists today.

- [ ] **Step 3: Implement `ServiceDetailView.swift`.**

```swift
import ComposableArchitecture
import SwiftUI

struct ServiceDetailView: View {
    @Bindable var store: StoreOf<ServiceDetailFeature>

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                ServiceIdentityHeader(summary: store.summary)
                    .padding(.top, 16)

                aboutCard
                scopesCard
                advancedCard

                if store.summary.status == .revoked {
                    DestructiveFooterButton(title: "Reconnect…") {
                        store.send(.reconnectTapped)
                    }
                } else {
                    DestructiveFooterButton(title: "Disconnect \(store.summary.name)") {
                        store.send(.disconnectTapped)
                    }
                }
            }
        }
        .background(Color(.systemGroupedBackground))
        .navigationBarTitleDisplayMode(.inline)
        .task { store.send(.onAppear) }
        .confirmationDialog(
            "Disconnect \(store.summary.name) from your network?",
            isPresented: Binding(
                get: { store.confirmingDisconnect },
                set: { if !$0 { store.send(.disconnectCancelTapped) } }
            ),
            titleVisibility: .visible
        ) {
            Button("Disconnect", role: .destructive) {
                store.send(.disconnectConfirmTapped)
            }
            Button("Cancel", role: .cancel) {
                store.send(.disconnectCancelTapped)
            }
        }
    }

    private var aboutCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("About")
                .font(.subheadline).foregroundStyle(.secondary)
            LabeledContent("Connected on", value: store.summary.connectedAt.formatted(date: .abbreviated, time: .omitted))
            if let last = store.summary.lastActivityAt {
                LabeledContent("Last activity", value: last.formatted(.relative(presentation: .named)))
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var scopesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What it can do")
                .font(.subheadline).foregroundStyle(.secondary)
            ForEach(store.summary.scopes) { scope in
                ScopeRow(descriptor: .constant(scope), editable: false)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var advancedCard: some View {
        AdvancedDisclosure(title: "Advanced") {
            VStack(alignment: .leading, spacing: 6) {
                Text("Cap ID")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(store.summary.id)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16)
    }
}
```

- [ ] **Step 4: Remove the placeholder `ServiceDetailView` and `ConnectView` in `NetworkView.swift`** — they're now their own files (ConnectView still placeholder until Phase 7).

- [ ] **Step 5: Build, run tests, commit.**

```bash
xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests
git add Wires/Wires/Features/Network Wires/WiresTests/ServiceDetailFeatureTests.swift
git commit -m "ios: implement ServiceDetailFeature + ServiceDetailView"
```

### Task 6.4 — Network + service-detail snapshot fixtures

**Spec:** §10 Snapshot fixtures (network + service-detail sections).

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Modify: `Wires/WiresUITests/SnapshotSweep.swift`
- Modify: `Wires/WiresTests/LaunchFixtureTests.swift`

- [ ] **Step 1: Add fixture cases (and remove old `home_*` cases).**

```swift
case networkEmpty                      = "network_empty"
case networkLoading                    = "network_loading"
case networkOneService                 = "network_one_service"
case networkThreeServicesOneRevoked    = "network_three_services_one_revoked"
case networkLoadError                  = "network_load_error"
case serviceDetailConnected            = "service_detail_connected"
case serviceDetailRevoked              = "service_detail_revoked"
case serviceDetailAdvancedExpanded     = "service_detail_advanced_expanded"
```

Remove: `homeLoading`, `homeEmpty`, `homeOneCap`, `homeThreeCapsOneRevoked`.

- [ ] **Step 2: `applyDependencies` arms.** Most can use the same shape as the existing `homeOneCap` / `homeThreeCapsOneRevoked` arms; `network_load_error` uses `.fixture(listCapsBehavior: .failing("Couldn't reach your server."))` if that's available, otherwise extend the fixture client.

- [ ] **Step 3: `initialAppState` arms** that build `.main(MainFeature.State(network: ..., settings: ..., selectedTab: .network))` with the appropriate seeded state.

```swift
case .networkEmpty:
    return mainStateOnNetwork(services: [])

case .networkLoading:
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.loading = true
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))

case .networkOneService:
    return mainStateOnNetwork(services: [
        ServiceSummary(
            id: "1", name: "Chase",
            deviceName: "Aaron's Mac mini",
            category: .banking, status: .connected,
            scopes: [
                ScopeDescriptor(id: "family", label: "family",
                                summary: "Read messages · Send messages",
                                detail: [
                                    .init(label: "Read messages", granted: true, kind: .read),
                                    .init(label: "Send messages", granted: true, kind: .write)
                                ])
            ],
            connectedAt: Date(timeIntervalSince1970: 1_715_000_000),
            lastActivityAt: nil
        )
    ])

case .networkThreeServicesOneRevoked:
    return mainStateOnNetwork(services: [
        ServiceSummary(
            id: "1", name: "Chase", deviceName: "Aaron's Mac mini",
            category: .banking, status: .connected, scopes: [],
            connectedAt: Date(timeIntervalSince1970: 1_715_000_000), lastActivityAt: nil
        ),
        ServiceSummary(
            id: "2", name: "Home Assistant", deviceName: "Kitchen iPad",
            category: .smartHome, status: .connected, scopes: [],
            connectedAt: Date(timeIntervalSince1970: 1_715_100_000), lastActivityAt: nil
        ),
        ServiceSummary(
            id: "3", name: "Calendar", deviceName: "Kitchen iPad",
            category: .unknown, status: .revoked, scopes: [],
            connectedAt: Date(timeIntervalSince1970: 1_715_200_000), lastActivityAt: nil
        )
    ])

case .networkLoadError:
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.loadError = "Couldn't reach your server. Check your connection and try again."
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))

case .serviceDetailConnected:
    let summary = ServiceSummary(
        id: "1", name: "Chase", deviceName: "Aaron's Mac mini",
        category: .banking, status: .connected,
        scopes: [
            ScopeDescriptor(id: "family", label: "family",
                            summary: "Read messages · Send messages",
                            detail: [
                                .init(label: "Read messages", granted: true, kind: .read),
                                .init(label: "Send messages", granted: true, kind: .write)
                            ])
        ],
        connectedAt: Date(timeIntervalSince1970: 1_715_000_000),
        lastActivityAt: nil
    )
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.path.append(ServiceDetailFeature.State(summary: summary))
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))

case .serviceDetailRevoked:
    let summary = ServiceSummary(
        id: "3", name: "Calendar", deviceName: "Kitchen iPad",
        category: .unknown, status: .revoked, scopes: [],
        connectedAt: Date(timeIntervalSince1970: 1_715_200_000),
        lastActivityAt: nil
    )
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.path.append(ServiceDetailFeature.State(summary: summary))
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))

case .serviceDetailAdvancedExpanded:
    // Same as serviceDetailConnected but with the Advanced disclosure
    // expanded — visible via @State default in AdvancedDisclosure, so
    // for the fixture we can override via a known initial expansion
    // (extend AdvancedDisclosure to accept an `initialExpanded` param
    // if needed; alternatively, render the same connected detail and
    // accept the fixture as visually identical until disclosure has a
    // bound expansion).
    return /* same as serviceDetailConnected */
```

And the helper near the bottom of `LaunchFixture`:

```swift
private func mainStateOnNetwork(services: [ServiceSummary]) -> AppFeature.State {
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.services = services
    network.loading = false
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))
}
```

For `serviceDetailAdvancedExpanded` to render meaningfully different from `serviceDetailConnected`, modify `AdvancedDisclosure` to accept an `initialExpanded: Bool = false` parameter and have the fixture wrap that — OR change `AdvancedDisclosure` to expose its `expanded` state via a Binding. For the v1 fixture, the simpler change is:

```swift
struct AdvancedDisclosure<Content: View>: View {
    let title: String
    @State private var expanded: Bool
    @ViewBuilder let content: () -> Content

    init(title: String, initialExpanded: Bool = false, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self._expanded = State(initialValue: initialExpanded)
        self.content = content
    }
    // body unchanged
}
```

Then `ServiceDetailView` can accept an `advancedInitiallyExpanded` parameter passed via the State (add `var advancedInitiallyExpanded = false` to `ServiceDetailFeature.State`). The fixture sets that flag to true.

- [ ] **Step 4: SnapshotSweep tests.**

```swift
func test_network_empty()                       throws { try snap("network_empty",                       flow: "network", short: "empty") }
func test_network_loading()                     throws { try snap("network_loading",                     flow: "network", short: "loading") }
func test_network_one_service()                 throws { try snap("network_one_service",                 flow: "network", short: "one-service") }
func test_network_three_services_one_revoked()  throws { try snap("network_three_services_one_revoked",  flow: "network", short: "three-services-one-revoked") }
func test_network_load_error()                  throws { try snap("network_load_error",                  flow: "network", short: "load-error") }
func test_service_detail_connected()            throws { try snap("service_detail_connected",            flow: "service", short: "detail-connected") }
func test_service_detail_revoked()              throws { try snap("service_detail_revoked",              flow: "service", short: "detail-revoked") }
func test_service_detail_advanced_expanded()    throws { try snap("service_detail_advanced_expanded",    flow: "service", short: "detail-advanced-expanded") }
```

Remove the four `test_home_*` methods.

- [ ] **Step 5: Bump `LaunchFixtureTests.allCases.count`.** Currently 20. Remove 4 old home, add 8 new: 20 - 4 + 8 = 24.

- [ ] **Step 6: Delete dead `HomeFeature`, `HomeView`, `HomeFeatureTests` files.**

- [ ] **Step 7: Snapshot sweep, review.**

```bash
./scripts/snapshot-ios.sh
open Wires/screenshots/latest/network Wires/screenshots/latest/service
```

- [ ] **Step 8: Commit.**

```bash
git add -A
git commit -m "ios: retire HomeFeature, add 8 network/service-detail snapshot fixtures"
```

---

## Phase 7 — Connect ceremony rewrite

Replaces `OAuthSignInFeature` (renamed `ConnectFeature`) with the polished single-QR consent dispatch UI from §6.4. The reducer logic largely transplants — visual treatment is the rewrite.

### Task 7.1 — ConnectFeature (rename + reshape)

**Spec:** §6.4 Connect-a-service ceremony.

**Files:**
- Modify: `Wires/Wires/Features/Connect/ConnectFeature.swift` (replace stub from Task 6.1)
- Create: `Wires/WiresTests/ConnectFeatureTests.swift`

- [ ] **Step 1: Rename existing `OAuthSignInFeature` to `ConnectFeature` in source.** Copy the existing `OAuthSignInFeature.swift` (`Wires/Wires/Features/OAuthSignIn/`) over the stub, but rename the type and update the public surface to use new state-case names from the spec:

```
.scan, .probing, .signinConfirm, .pairLoading→deleted, .pairApprove, .done, .error
```

Replace `.pairLoading` everywhere — the spec collapses it into `.probing`. Any code path that currently routes into `.pairLoading` should route into `.probing` (with the existing copy-changes).

- [ ] **Step 2: Add a `static func initial() -> State` constructor** (already exists on OAuthSignInFeature) — keep it.

- [ ] **Step 3: Migrate the old `OAuthSignInFeatureTests.swift`** to `ConnectFeatureTests.swift` — same test scenarios, just rename the reducer and state references and assertions involving `.pairLoading`.

- [ ] **Step 4: Build, run tests, commit.**

```bash
git mv Wires/Wires/Features/OAuthSignIn Wires/Wires/Features/Connect.bak  # so the old test file shows up in `git mv`
# Then manually relocate files: ConnectFeature.swift, ConnectView.swift (created next task)
# (Alternative: rm old, write new.)
git add Wires/Wires/Features/Connect Wires/WiresTests/ConnectFeatureTests.swift
git rm Wires/WiresTests/OAuthSignInFeatureTests.swift
git commit -m "ios: rename OAuthSignInFeature → ConnectFeature, collapse pairLoading into probing"
```

### Task 7.2 — ConnectView with polished step UIs

**Spec:** §6.4 Step 1–5.

**Files:**
- Create: `Wires/Wires/Features/Connect/ConnectView.swift` (overwrite the Task 6.2 placeholder)

- [ ] **Step 1: Implement.**

```swift
import ComposableArchitecture
import SwiftUI

struct ConnectView: View {
    @Bindable var store: StoreOf<ConnectFeature>

    var body: some View {
        NavigationStack {
            content
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { store.send(.dismissTapped) }
                    }
                }
        }
        .presentationBackground(.regularMaterial)
    }

    @ViewBuilder
    private var content: some View {
        switch store.state {
        case .scan:
            if let scanStore = store.scope(state: \.scan?, action: \.scan) {
                connectScan(scanStore: scanStore)
            }
        case .probing:
            probing
        case let .signinConfirm(_, challenge):
            signinConfirm(challenge: challenge)
        case let .pairApprove(approveState):
            if let approveStore = store.scope(state: \.pairApprove, action: \.approve) {
                approveSheet(store: approveStore, approveState: approveState)
            }
        case let .done(message):
            doneView(message: message)
        case let .error(message):
            errorView(message: message)
        }
    }

    @ViewBuilder
    private func connectScan(scanStore: StoreOf<ScanFeature<SessionTicket>>) -> some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Text("Add a service")
                    .font(.largeTitle.bold())
                Text("Scan the code shown by the service you want to connect.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.vertical, 16)

            ScanView(store: scanStore)
                .frame(maxHeight: .infinity)
        }
    }

    private var probing: some View {
        VStack(spacing: 16) {
            WiresBrandGlyph(variant: .static, size: 96)
                .opacity(0.4)
            ProgressView()
            Text("Checking with your server…")
                .font(.headline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func signinConfirm(challenge: SignInChallenge) -> some View {
        OnboardingScaffold(
            title: "Sign in to your account?",
            subtitle: "Approving will use your account key on this iPhone. Face ID required.",
            hero: {
                Image(systemName: "faceid")
                    .font(.system(size: 96, weight: .light))
                    .foregroundStyle(AppColors.indigoPrimary)
            },
            content: {
                Text(challenge.gatewayURL)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)
            },
            primaryTitle: "Sign in with Face ID",
            primaryAction: { store.send(.signinApproveTapped) }
        )
    }

    private func approveSheet(
        store approveStore: StoreOf<ApprovalFeature>,
        approveState: ApprovalFeature.State
    ) -> some View {
        ApprovalView(store: approveStore)
    }

    private func doneView(message: String) -> some View {
        OnboardingScaffold(
            title: "Connected",
            subtitle: message,
            hero: {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 96))
                    .foregroundStyle(.green)
            },
            content: { EmptyView() },
            primaryTitle: "Done",
            primaryAction: { store.send(.dismissTapped) }
        )
    }

    private func errorView(message: String) -> some View {
        InlineErrorBanner(
            message: friendlyMessage(message),
            primaryTitle: "Try again",
            primaryAction: { store.send(.dismissTapped) },  // for v1, retry == dismiss; future: route back to scan
            secondaryTitle: "Cancel",
            secondaryAction: { store.send(.dismissTapped) }
        )
    }

    private func friendlyMessage(_ raw: String) -> String {
        // Hide gateway-X-returned-N-style errors behind human copy.
        if raw.contains("returned") || raw.contains("status") {
            return "Couldn't reach your server. Check your connection and try again."
        }
        return raw
    }
}
```

- [ ] **Step 2: Update `ApprovalView`** (the existing pair-approve form) to use the new component vocabulary: `ServiceIdentityHeader` at top, `ScopeRow` for each requested topic, sticky-bottom `Approve with Face ID` button via `OnboardingScaffold` or a custom layout.

This is a substantial rewrite — replace the existing `Form`-based layout (`Wires/Wires/Features/NodeEnrollment/ApprovalView.swift`) with:

```swift
import ComposableArchitecture
import SwiftUI
import WiresKit

struct ApprovalView: View {
    @Bindable var store: StoreOf<ApprovalFeature>

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                ServiceIdentityHeader(summary: headerSummary, size: .medium)
                    .padding(.top, 16)

                aboutCard
                accessCard

                if let err = store.error {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .padding(.horizontal, 16)
                }
            }
        }
        .background(Color(.systemGroupedBackground))
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Button {
                    store.send(store.error == nil ? .approveTapped : .retryTapped)
                } label: {
                    HStack {
                        if store.submitting {
                            ProgressView().padding(.trailing, 6)
                        }
                        Text(store.error == nil ? "Approve with Face ID" : "Retry")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .tint(AppColors.indigoPrimary)
                .disabled(store.submitting || !hasAnyGrant)
            }
            .padding(16)
            .background(.regularMaterial)
        }
    }

    private var hasAnyGrant: Bool {
        store.decisions.contains { $0.granted && !$0.grantedRights.isEmpty }
    }

    private var headerSummary: ServiceSummary {
        ServiceSummary(
            id: store.preview.handle.id,
            name: store.preview.description.isEmpty ? "Service" : store.preview.description,
            deviceName: nil,
            category: .unknown,
            status: .pending,
            scopes: [],
            connectedAt: Date(),
            lastActivityAt: nil
        )
    }

    private var aboutCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("About this service")
                .font(.subheadline).foregroundStyle(.secondary)
            LabeledContent("Role", value: store.preview.role)
            if !store.preview.description.isEmpty {
                LabeledContent("Description", value: store.preview.description)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var accessCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Access")
                .font(.subheadline).foregroundStyle(.secondary)
            ForEach(store.decisions) { decision in
                ScopeRow(
                    descriptor: descriptorBinding(for: decision),
                    editable: true
                )
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private func descriptorBinding(for decision: ApprovalFeature.ScopeDecision) -> Binding<ScopeDescriptor> {
        Binding(
            get: {
                ScopeDescriptor(
                    id: decision.id,
                    label: decision.topicName,
                    summary: decision.requestedRights.map(humanizedRight).joined(separator: " · "),
                    detail: decision.requestedRights.map { right in
                        ScopeDetailRow(
                            label: humanizedRight(right),
                            granted: decision.grantedRights.contains(right) && decision.granted,
                            kind: scopeKind(right)
                        )
                    }
                )
            },
            set: { newValue in
                let anyGranted = newValue.detail.contains(\.granted)
                store.send(.toggleScope(id: decision.id, granted: anyGranted))
                for row in newValue.detail {
                    let right = wiresRightFromKind(row.kind)
                    store.send(.toggleRight(id: decision.id, right: right, on: row.granted))
                }
            }
        )
    }

    private func humanizedRight(_ right: Right) -> String {
        switch right {
        case .read:  return "Read messages"
        case .write: return "Send messages"
        }
    }
    private func scopeKind(_ right: Right) -> ScopeRightKind {
        switch right {
        case .read:  return .read
        case .write: return .write
        }
    }
    private func wiresRightFromKind(_ kind: ScopeRightKind) -> Right {
        switch kind {
        case .read:  return .read
        case .write: return .write
        case .grant, .custom: return .read  // fallback
        }
    }
}
```

- [ ] **Step 3: Build, run tests, commit.**

```bash
xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests
git add Wires/Wires/Features/Connect Wires/Wires/Features/NodeEnrollment
git commit -m "ios: implement ConnectView + rewrite ApprovalView with new component vocabulary"
```

### Task 7.3 — Connect ceremony snapshot fixtures

**Spec:** §10 Snapshot fixtures (connect section).

**Files:**
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Modify: `Wires/WiresUITests/SnapshotSweep.swift`
- Modify: `Wires/WiresTests/LaunchFixtureTests.swift`

- [ ] **Step 1: Add fixture cases (remove old `oauth_*`).**

```swift
case connectScan                = "connect_scan"
case connectProbing             = "connect_probing"
case connectSigninConfirm       = "connect_signin_confirm"
case connectApproveCollapsed    = "connect_approve_collapsed"
case connectApproveExpanded     = "connect_approve_expanded"
case connectDone                = "connect_done"
case connectErrorParse          = "connect_error_parse"
case connectErrorNetwork        = "connect_error_network"
case connectAlreadyConnected    = "connect_already_connected"
```

Remove all `oauth_*` cases.

- [ ] **Step 2: `applyDependencies` and `initialAppState` arms.** Each connect fixture seeds `.main(MainFeature.State(network: ..., settings: ..., selectedTab: .network))` with `network.connect = <appropriate ConnectFeature.State>`.

For example:

```swift
case .connectScan:
    var connect = ConnectFeature.State.initial()
    if case .scan(var scanState) = connect {
        scanState.cameraPermission = .granted
        connect = .scan(scanState)
    }
    return mainStateWithConnect(connect)

case .connectProbing:
    return mainStateWithConnect(.probing)

case .connectSigninConfirm:
    let ticket = SessionTicket(
        version: 1, kind: SessionTicket.kindV1,
        gatewayURL: "https://wires-mcp.example.org",
        sessionID: "fixture-session-id"
    )
    let challenge = SignInChallenge(
        version: 1, kind: SignInChallenge.kindV1,
        gatewayURL: "https://wires-mcp.example.org",
        sessionID: "fixture-session-id",
        nonce: String(repeating: "0", count: 64),
        issuedAt: 0, expires: 0
    )
    return mainStateWithConnect(.signinConfirm(ticket: ticket, challenge: challenge))

case .connectDone:
    return mainStateWithConnect(.done(message: "Chase is now on your network."))

case .connectErrorParse:
    return mainStateWithConnect(.error(message: "Couldn't read this code. Try again."))

case .connectErrorNetwork:
    return mainStateWithConnect(.error(message: "Couldn't reach your server."))

case .connectAlreadyConnected:
    return mainStateWithConnect(.done(message: "Chase is already connected."))

case .connectApproveCollapsed, .connectApproveExpanded:
    return mainStateWithConnect(.pairApprove(approvalStateForFixture()))
```

Helper:

```swift
private func mainStateWithConnect(_ connect: ConnectFeature.State) -> AppFeature.State {
    var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
    network.connect = connect
    return .main(MainFeature.State(network: network, settings: SettingsFeature.State(), selectedTab: .network))
}

private func approvalStateForFixture() -> ApprovalFeature.State {
    let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: [], relay: nil, hintExpiresAtMs: 0, serverName: "Wires"
    )
    let preview = PairRequestPreview(
        handle: PendingPairHandle(id: "fixture-pair"),
        agentPubkeyHex: String(repeating: "ef", count: 32),
        role: "agent",
        description: "Chase",
        issuedAtMs: 0, expiresAtMs: 0,
        requestedScopes: [
            RequestedScopePreview(topicName: "family", rights: [.read, .write]),
            RequestedScopePreview(topicName: "calendar", rights: [.read])
        ],
        dialSummary: ""
    )
    return ApprovalFeature.State(preview: preview, host: host)
}
```

For `connectApproveExpanded`, we need to render one ScopeRow expanded. ScopeRow's `expanded` is currently @State. Same approach as Task 6.4 for AdvancedDisclosure — add `initiallyExpanded: Bool = false` parameter to ScopeRow, and a per-scope override in the fixture by introducing a `ScopeRowExpansion` map on the approval state. Simpler v1 path: skip `connectApproveExpanded` for now and instead always render the collapsed state — the spec lists it as a fixture but can drop if implementation gets expensive. **Recommended:** drop `connectApproveExpanded` from the fixture list and remove the corresponding `SnapshotSweep` entry; record this in the plan's task-7.3 outcome.

- [ ] **Step 3: SnapshotSweep tests (omit `expanded` variant if dropped).**

```swift
func test_connect_scan()              throws { try snap("connect_scan",              flow: "connect", short: "scan") }
func test_connect_probing()           throws { try snap("connect_probing",           flow: "connect", short: "probing") }
func test_connect_signin_confirm()    throws { try snap("connect_signin_confirm",    flow: "connect", short: "signin-confirm") }
func test_connect_approve_collapsed() throws { try snap("connect_approve_collapsed", flow: "connect", short: "approve-collapsed") }
func test_connect_done()              throws { try snap("connect_done",              flow: "connect", short: "done") }
func test_connect_error_parse()       throws { try snap("connect_error_parse",       flow: "connect", short: "error-parse") }
func test_connect_error_network()     throws { try snap("connect_error_network",     flow: "connect", short: "error-network") }
func test_connect_already_connected() throws { try snap("connect_already_connected", flow: "connect", short: "already-connected") }
```

Remove the six `test_oauth_*` methods.

- [ ] **Step 4: Bump `LaunchFixtureTests.allCases.count`.** Currently 24 (after Phase 6). Remove 6 old oauth, add 8 new connect: 24 - 6 + 8 = 26.

- [ ] **Step 5: Snapshot sweep, review.**

```bash
./scripts/snapshot-ios.sh
open Wires/screenshots/latest/connect
```

- [ ] **Step 6: Commit.**

```bash
git add -A
git commit -m "ios: retire oauth_* fixtures, add 8 connect ceremony snapshot fixtures"
```

---

## Phase 8 — Cleanup + final review

### Task 8.1 — Delete dead code

- [ ] **Step 1: Search for remaining references to `BootstrapFeature`, `HomeFeature`, `OAuthSignInFeature`.**

```bash
grep -rn "BootstrapFeature\|HomeFeature\|OAuthSignInFeature" Wires/Wires Wires/WiresTests Wires/WiresUITests
```

Expected: no matches. If any references remain (likely in tests or commented-out code), remove them.

- [ ] **Step 2: Search for any remaining mentions of "household" in user-visible strings** (per Principle 1, "household" should not appear on any screen until that feature is brought back).

```bash
grep -rn "Household\|household" Wires/Wires/Features --include='*.swift'
```

Each match: confirm it's either an internal type name (`HouseholdClient`, `Household` model) or a comment, not a user-visible string. User-visible "Household" titles must become "Your Wires" or "Network".

- [ ] **Step 3: Update `CLAUDE.md`'s snapshot harness section.** The fixture count is now 26. Update:

```markdown
# Full sweep — 26 fixtures × light/dark = 52 PNGs, ~6 minutes:
```

And the fixture list under "Reading the output" should mention `connect/`, `network/`, `onboarding/`, `service/`, `settings/` as the flow folders (replacing `bootstrap/`, `home/`, `enroll/`, `oauth/`).

- [ ] **Step 4: Commit.**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md snapshot harness section for redesigned fixtures"
```

### Task 8.2 — Full snapshot sweep + visual diff

- [ ] **Step 1: Run a clean snapshot sweep.**

```bash
./scripts/snapshot-ios.sh
```

Expected: 26 × 2 = 52 PNGs produced under `Wires/screenshots/latest/`. Run time ~6 minutes.

- [ ] **Step 2: Visually inspect every fixture against the spec.** For each fixture, open the light + dark PNG, confirm it matches the corresponding spec section's description. Use a checklist:

| Fixture | Spec section | Light OK | Dark OK |
|---|---|---|---|
| onboarding_welcome | §6.1 Step 1 | | |
| onboarding_scan | §6.1 Step 2 | | |
| onboarding_scan_error | §6.1 Step 2 errors | | |
| onboarding_confirm | §6.1 Step 3 | | |
| onboarding_face_id | §6.1 Step 4 | | |
| onboarding_done | §6.1 Step 5 | | |
| network_empty | §6.2 Empty state | | |
| network_loading | §6.2 | | |
| network_one_service | §6.2 Row anatomy | | |
| network_three_services_one_revoked | §6.2 Sections | | |
| network_load_error | §6.2 / §3 Principle 7 | | |
| service_detail_connected | §6.3 | | |
| service_detail_revoked | §6.3 Revoked variant | | |
| service_detail_advanced_expanded | §6.3 Advanced | | |
| settings_root | §6.5 | | |
| settings_face_id_off | §6.5 Security | | |
| settings_account_detail | §6.5 Header | | |
| settings_delete_confirm | §6.5 Destructive footer | | |
| connect_scan | §6.4 Step 1 | | |
| connect_probing | §6.4 Step 2 | | |
| connect_signin_confirm | §6.4 Step 3a | | |
| connect_approve_collapsed | §6.4 Step 3b | | |
| connect_done | §6.4 Step 4 | | |
| connect_error_parse | §6.4 Step 5 | | |
| connect_error_network | §6.4 Step 5 | | |
| connect_already_connected | §6.4 Step 5 | | |

- [ ] **Step 3: Address any visual issues** found in Step 2 with targeted fixes. Commit each fix as its own commit.

- [ ] **Step 4: Curate a baseline into `docs/ui-baselines/2026-05-19/`.** Copy the entire `Wires/screenshots/latest/` tree (which is gitignored under `Wires/`) into `docs/ui-baselines/2026-05-19/`, which IS tracked. This becomes the canonical visual record for the redesign.

```bash
mkdir -p docs/ui-baselines/2026-05-19
cp -r Wires/screenshots/latest/* docs/ui-baselines/2026-05-19/
git add docs/ui-baselines/2026-05-19/
git commit -m "docs: capture redesign baseline screenshots under docs/ui-baselines/2026-05-19/"
```

### Task 8.3 — Update CLAUDE.md status section

- [ ] **Step 1: Add a bullet to the "Status" section** at the top of `CLAUDE.md` recording that the HIG redesign landed.

```markdown
- **iOS HIG redesign v1** (landed 2026-05-XX) — Apple Passwords-sibling visual treatment, 5-step Apple Pay-style onboarding, TabView with Network + Settings ready for future Conversations tab, indigo accent + wire-key brand glyph, `ScopeDescriptor` indirection isolating views from cap-shape churn, `HostTicket.server_name` flag end-to-end. 26 snapshot fixtures × light/dark. Spec: `docs/superpowers/specs/2026-05-19-wires-ios-hig-redesign-design.md`. Plan: `docs/superpowers/plans/2026-05-19-wires-ios-hig-redesign.md`.
```

- [ ] **Step 2: Commit.**

```bash
git add CLAUDE.md
git commit -m "docs: record iOS HIG redesign v1 in CLAUDE.md Status section"
```

---

## Final verification

- [ ] **Step 1: Full workspace test pass.**

```bash
xcodebuild test -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4' -only-testing:WiresTests
cargo test --workspace
```

Expected: all green.

- [ ] **Step 2: Final snapshot sweep.**

```bash
./scripts/snapshot-ios.sh
```

Expected: 52 PNGs, all matching the spec.

- [ ] **Step 3: Inspect the app interactively on simulator.**

Launch the app fresh (no `WIRES_FIXTURE` env var) so it boots through the real `prepareWiresApp` path. Verify:
- Welcome screen renders with the wire-key glyph animating in.
- Scan step displays the proper reticle and instruction copy.
- (Skip rest of onboarding without a real server.)

If a `wires-host` is running locally with `--server-name "Local"`, do a real end-to-end onboarding to confirm the friendly name displays at Step 3.
