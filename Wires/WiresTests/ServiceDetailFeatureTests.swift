import ComposableArchitecture
import Foundation
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
