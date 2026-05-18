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
            agentPubkeyHex: String(repeating: "22", count: 32),
            agentAlias: "chat-agent: Bob",
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
                    agentPubkeyHex: cap.agentPubkeyHex,
                    agentAlias: cap.agentAlias,
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
    func approveAgent_presentsEnrollmentSheet() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        }

        await store.send(.approveAgentTapped) {
            $0.agentEnrollment = AgentEnrollmentFeature.State()
        }
    }

    @Test
    func enrollmentDismiss_clearsSheet() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.agentEnrollment = AgentEnrollmentFeature.State()

        let store = TestStore(initialState: initial) { HomeFeature() }

        await store.send(.agentEnrollment(.presented(.dismissTapped))) {
            $0.agentEnrollment = nil
        }
    }
}
