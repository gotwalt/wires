import ComposableArchitecture
import Foundation
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
            $0.keychainClient = .testValue
        }
        await store.send(.onAppear) { $0.loading = true }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.services = [CapToServiceMapper.summary(from: cap)]
        }
    }
}
