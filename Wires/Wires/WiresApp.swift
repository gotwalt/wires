import SwiftUI
import WiresKit
import ComposableArchitecture

/// Renamed from `WiresApp` to avoid clashing with `WiresKit.WiresApp`
/// (the UniFFI-generated FFI class) within this module.
@main
struct WiresIOSApp: App {
    var body: some Scene {
        WindowGroup {
            Text("WiresKit + TCA loaded")
        }
    }
}
