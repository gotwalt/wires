import ComposableArchitecture
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
        case .main:
            if let scoped = store.scope(state: \.main, action: \.main) {
                MainView(store: scoped)
            }
        }
    }
}
