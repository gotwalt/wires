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
            $0.fabricClient = .fixture()
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
            $0.fabricClient = .fixture()
        }
        await store.send(.scan(.decodedPayload(host))) {
            $0.confirmedHost = host
            $0.step = .confirm
        }
    }
}
