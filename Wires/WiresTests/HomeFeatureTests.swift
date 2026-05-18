import ComposableArchitecture
import Foundation
import Testing
@testable import Wires

@MainActor
struct HomeFeatureTests {
    static let pubkey = String(repeating: "ab", count: 32)

    @Test
    func onAppear_emptyStore_loadsZeroCaps() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.capsLoaded) {
            $0.loading = false
            $0.caps = []
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
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.capsLoaded) {
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
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.capsLoadFailed) {
            $0.loading = false
            $0.loadError = "Boom()"
        }
    }

    @Test
    func approveNode_presentsEnrollmentSheet() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        }

        await store.send(.approveNodeTapped) {
            $0.nodeEnrollment = NodeEnrollmentFeature.State()
        }
    }

    @Test
    func enrollmentDismiss_clearsSheet() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.nodeEnrollment = NodeEnrollmentFeature.State()

        let store = TestStore(initialState: initial) { HomeFeature() }

        await store.send(.nodeEnrollment(.presented(.dismissTapped))) {
            $0.nodeEnrollment = nil
        }
    }
}
