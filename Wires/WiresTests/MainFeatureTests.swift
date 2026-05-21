import ComposableArchitecture
import Testing
@testable import Wires

@Suite("MainFeature")
struct MainFeatureTests {
    @Test("forwards network actions to the network child")
    func forwardsNetwork() async {
        let store = await TestStore(
            initialState: MainFeature.State(
                network: NetworkFeature.State(rootPubkeyHex: "ab"),
                settings: SettingsFeature.State(),
                selectedTab: .network
            )
        ) {
            MainFeature()
        } withDependencies: {
            $0.fabricClient = .testValue
            $0.wiresClient = .testValue
            $0.keychainClient = .testValue
        }
        _ = store
    }
}
