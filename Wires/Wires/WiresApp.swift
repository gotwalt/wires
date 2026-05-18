import ComposableArchitecture
import SwiftUI
import WiresKit

/// Renamed from `WiresApp` to avoid clashing with `WiresKit.WiresApp`
/// (the UniFFI-generated FFI class) within this module.
@main
struct WiresIOSApp: App {
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
        switch store.state {
        case .launching:
            ProgressView()
                .task { store.send(.onAppear) }
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
