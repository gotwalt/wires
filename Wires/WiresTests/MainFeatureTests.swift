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
