import ComposableArchitecture
import Foundation
import Testing
import WiresKit
@testable import Wires

@MainActor
struct HomeFeatureTests {
    static let pubkey = String(repeating: "ab", count: 32)

    static let sampleHost = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["127.0.0.1:11204"],
        relay: nil,
        hintExpiresAtMs: 0
    )

    @Test
    func onAppear_emptyStore_loadsZeroCaps() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.caps = []
            $0.host = nil
        }
    }

    @Test
    func onAppear_populatesCapsFromStore() async {
        let cap = CapRecord(
            capIdHex: String(repeating: "11", count: 16),
            nodePubkeyHex: String(repeating: "22", count: 32),
            nodeAlias: "chat-node: Bob",
            topicNames: ["home.notes"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [cap] }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.caps = [
                HomeFeature.CapSummary(
                    id: cap.capIdHex,
                    nodePubkeyHex: cap.nodePubkeyHex,
                    nodeAlias: cap.nodeAlias,
                    topicNames: cap.topicNames,
                    rights: cap.rights,
                    issuedAt: cap.issuedAt,
                    revokedAt: nil
                )
            ]
            $0.host = nil
        }
    }

    @Test
    func onAppear_listFailure_surfacesError() async {
        struct Boom: Error {}
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { throw Boom() }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loadFailed) {
            $0.loading = false
            $0.loadError = "Boom()"
        }
    }

    @Test
    func approveNode_withoutHost_isNoop() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        }

        await store.send(.approveNodeTapped)
        #expect(store.state.nodeEnrollment == nil)
    }

    @Test
    func approveNode_withHost_presentsEnrollmentSheet() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.host = Self.sampleHost
        let store = TestStore(initialState: initial) { HomeFeature() }

        await store.send(.approveNodeTapped) {
            $0.nodeEnrollment = .scan(NodeEnrollmentFeature.ScanStepState(host: Self.sampleHost))
        }
    }

    @Test
    func enrollmentDismiss_clearsSheet() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.host = Self.sampleHost
        initial.nodeEnrollment = .initial(host: Self.sampleHost)

        let store = TestStore(initialState: initial) { HomeFeature() }

        await store.send(.nodeEnrollment(.presented(.dismissTapped))) {
            $0.nodeEnrollment = nil
        }
    }
}
