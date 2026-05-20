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
