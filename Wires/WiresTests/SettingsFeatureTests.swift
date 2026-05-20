import ComposableArchitecture
import Testing
@testable import Wires

@Suite("SettingsFeature")
struct SettingsFeatureTests {
    @Test("starts with no state mutation")
    func startsBare() async {
        let store = await TestStore(initialState: SettingsFeature.State()) {
            SettingsFeature()
        }
        _ = store
    }

    @Test("loaded action populates state fields")
    func loadedPopulates() async {
        let store = await TestStore(initialState: SettingsFeature.State()) {
            SettingsFeature()
        } withDependencies: {
            $0.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: "ab",
                    hostEndpointIdHex: "cd",
                    hostRelayURL: "https://wires.example.org"
                )
            )
        }
        await store.send(.loaded(
            serverName: "Wires",
            relayURL: "https://usw1-1.relay.n0.iroh-canary.iroh.link./",
            rootPubkeyHex: "ab",
            faceIDEnabled: true
        )) {
            $0.serverName = "Wires"
            $0.relayURL = "https://usw1-1.relay.n0.iroh-canary.iroh.link./"
            $0.rootPubkeyHex = "ab"
            $0.faceIDEnabled = true
            $0.loading = false
        }
    }
}
